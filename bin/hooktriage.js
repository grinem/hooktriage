#!/usr/bin/env node
/**
 * HookTriage CLI & Zero-Trust MCP Server (0 dependencies, 0 network calls by default)
 * Usage:
 *   npx -y github:grinem/hooktriage audit ./workflow.json
 *   npx -y github:grinem/hooktriage scan ./workflow.json
 *   npx -y github:grinem/hooktriage fix ./workflow.json --key=HT-PRO-...
 *   npx -y github:grinem/hooktriage --mcp
 */
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";

const KIT_WEB_URL = "https://hooktriage.com/kit";
const KIT_STRIPE_URL = "https://www.agensi.io/r/HOOKTRIAGE?to=/skills/hooktriage-n8n-production-hardening-kit&utm_source=cli";
const LICENSE_PUBLIC_KEY_DER_B64 = "MCowBQYDK2VwAyEAZvA8QkVBYUdPOHs4oc9wPUn6/HHGousqvitfkogsKks="; // Ed25519 public key (offline verify only)

const RED = process.stdout.isTTY ? "\x1b[31m" : "";
const GREEN = process.stdout.isTTY ? "\x1b[32m" : "";
const YELLOW = process.stdout.isTTY ? "\x1b[33m" : "";
const CYAN = process.stdout.isTTY ? "\x1b[36m" : "";
const BOLD = process.stdout.isTTY ? "\x1b[1m" : "";
const RESET = process.stdout.isTTY ? "\x1b[0m" : "";

function scrubSecrets(val) {
  return String(val || "")
    .replace(/\b(sk_live_|sk_test_|sk-|re_|ghp_|gho_|whsec_|xox[baprs]-|AIza)[A-Za-z0-9_/+=-]{10,}\b/g, "[REDACTED_KEY]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS]")
    .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b/g, "[REDACTED_JWT]")
    .replace(/(Bearer\s+)[A-Za-z0-9._-]{12,}/gi, "$1[REDACTED_TOKEN]")
    .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");
}

function verifyProLicenseKey(rawKey) {
  const cleaned = String(rawKey || "").trim().replace(/^['"]|['"]$/g, "");
  if (!cleaned) {
    return { valid: false, reason: "Missing license key (--key=HT-PRO-...)." };
  }
  const match = /^HT-PRO-([A-Z0-9]{4,10})-([A-Z0-9]{4,12})-([A-Za-z0-9_-]{86})$/.exec(cleaned);
  if (!match) {
    return {
      valid: false,
      reason: "Invalid license key format. Expected HT-PRO-<EDITION>-<SERIAL>-<SIGNATURE>.",
    };
  }
  const [, edition, serial, sigB64] = match;
  try {
    const pub = crypto.createPublicKey({
      key: Buffer.from(LICENSE_PUBLIC_KEY_DER_B64, "base64"),
      format: "der",
      type: "spki",
    });
    const ok = crypto.verify(null, Buffer.from(`HT-PRO:${edition}:${serial}`, "utf8"), pub, Buffer.from(sigB64, "base64url"));
    if (!ok) {
      return { valid: false, reason: "License signature verification failed." };
    }
  } catch (e) {
    return { valid: false, reason: "License signature verification failed." };
  }
  return { valid: true, edition, serial, key: cleaned };
}

function scanWorkflowObject(parsed) {
  const findings = [];
  if (!parsed || !Array.isArray(parsed.nodes)) {
    return {
      ok: false,
      error: "Input JSON does not contain an n8n `nodes` array.",
      findings: [],
      summary: "Invalid n8n workflow export JSON.",
    };
  }

  const wfName = scrubSecrets(parsed.name || "Unnamed n8n Workflow").slice(0, 120);
  const settings = parsed.settings || {};

  const isErrorHandler = parsed.nodes.some((n) => /errorTrigger/i.test(String(n.type || "")));
  if (!isErrorHandler && !settings.errorWorkflow) {
    findings.push({
      severity: "HIGH",
      category: "missing_error_workflow",
      node: "Workflow Settings",
      detail: "No `settings.errorWorkflow` configured. Unhandled runtime exceptions will crash silently without alerting ops.",
      fix: "Attach https://github.com/grinem/n8n-ai-watchdog as this workflow's Error Workflow.",
    });
  }

  const externalNodes = parsed.nodes.filter((n) =>
    /httpRequest|openAi|langchain|webhook|stripe|shopify|anthropic|gemini|slack/i.test(String(n.type || ""))
  );

  for (const n of externalNodes) {
    const nName = scrubSecrets(n.name || n.type || "Node").slice(0, 80);
    const params = n.parameters || {};
    const opts = params.options || {};

    if (/httpRequest|openAi|langchain|anthropic|gemini/i.test(String(n.type || "")) && !opts.timeout) {
      findings.push({
        severity: "MEDIUM",
        category: "missing_http_timeout",
        node: nName,
        detail: "External API/LLM node has no explicit HTTP timeout option (risk of hung worker queues).",
        fix: "Set Parameters -> Options -> Timeout (e.g., 15000 ms) + Continue/Error branch.",
      });
    }
    if (!n.retryOnFail && !/webhook$/i.test(String(n.type || ""))) {
      findings.push({
        severity: "HIGH",
        category: "missing_retry_on_fail",
        node: nName,
        detail: "API/integration node lacks `retryOnFail: true`. Transient HTTP 429 or 502 spikes will silently drop items.",
        fix: "Enable Retry On Fail (`maxTries: 3`, `waitBetweenTries: 2000`) under Node Settings.",
      });
    }
    if (/webhook/i.test(String(n.type || "")) && params.responseMode === "lastNode") {
      findings.push({
        severity: "HIGH",
        category: "sync_webhook_cutoff",
        node: nName,
        detail: "Webhook uses synchronous `responseMode: lastNode`. Platforms like Shopify enforce a 5s webhook timeout and deactivate hooks that stall.",
        fix: "Respond immediately (`Respond to Webhook` / `onReceived`) before downstream API/LLM calls, or push to a dead-letter queue.",
      });
    }
  }

  const aiNodes = parsed.nodes.filter((n) => /langchain|agent|openAi|anthropic|gemini/i.test(String(n.type || "")));
  if (aiNodes.length > 0) {
    const hasIf = parsed.nodes.some((n) => /n8n-nodes-base\.if$|n8n-nodes-base\.switch$/i.test(String(n.type || "")));
    if (!hasIf) {
      findings.push({
        severity: "MEDIUM",
        category: "unguarded_ai_output",
        node: scrubSecrets(aiNodes[0].name || "AI Node"),
        detail: "AI/LLM node without downstream IF/Switch validation can finish green while returning empty `[]` or malformed JSON.",
        fix: "Add an IF guard checking non-empty structured output and trigger Watchdog sub-workflow on the false branch.",
      });
    }
  }

  return {
    ok: true,
    workflow_name: wfName,
    node_count: parsed.nodes.length,
    scanned_locally_bytes_uploaded: 0,
    findings,
    watchdog_template: "https://github.com/grinem/n8n-ai-watchdog",
    docs_and_remediation: "https://hooktriage.com",
  };
}

function hardenWorkflowObject(parsed) {
  if (!parsed || !Array.isArray(parsed.nodes)) {
    throw new Error("Input JSON does not contain an n8n `nodes` array.");
  }

  const hardened = structuredClone(parsed);
  const patches = [];
  hardened.settings = hardened.settings && typeof hardened.settings === "object" ? hardened.settings : {};
  hardened.connections = hardened.connections && typeof hardened.connections === "object" ? hardened.connections : {};

  const isErrorHandler = hardened.nodes.some((n) => /errorTrigger/i.test(String(n.type || "")));
  if (!isErrorHandler && !hardened.settings.errorWorkflow) {
    hardened.settings.errorWorkflow = "hooktriage-watchdog-error-handler";
    hardened.settings.saveExecutionProgress = true;
    hardened.settings.saveDataErrorExecution = "all";
    patches.push("Configured settings.errorWorkflow = 'hooktriage-watchdog-error-handler' & error execution retention");
  }

  let maxX = 240;
  let maxY = 300;
  const errorBranchSources = [];

  for (const node of hardened.nodes) {
    if (Array.isArray(node.position) && node.position.length >= 2) {
      maxX = Math.max(maxX, Number(node.position[0]) || 240);
      maxY = Math.max(maxY, Number(node.position[1]) || 300);
    }
    const nType = String(node.type || "");
    const nName = String(node.name || nType || "Node");

    if (/httpRequest|openAi|langchain|webhook|stripe|shopify|anthropic|gemini|slack/i.test(nType)) {
      node.parameters = node.parameters && typeof node.parameters === "object" ? node.parameters : {};

      if (/httpRequest|openAi|langchain|anthropic|gemini/i.test(nType)) {
        node.parameters.options =
          node.parameters.options && typeof node.parameters.options === "object" ? node.parameters.options : {};
        if (!node.parameters.options.timeout) {
          node.parameters.options.timeout = 15000;
          patches.push(`Set HTTP timeout=15000ms on '${nName}'`);
        }
      }

      if (!/webhook$/i.test(nType)) {
        if (!node.retryOnFail) {
          node.retryOnFail = true;
          node.maxTries = Math.max(Number(node.maxTries || 0), 3);
          node.waitBetweenTries = Math.max(Number(node.waitBetweenTries || 0), 2000);
          patches.push(`Enabled retryOnFail (maxTries=3, backoff=2000ms) on '${nName}'`);
        }
        if (!node.onError) {
          node.onError = "continueErrorOutput";
          errorBranchSources.push(nName);
          patches.push(`Enabled onError='continueErrorOutput' (DLQ routing) on '${nName}'`);
        }
      }

      if (/webhook/i.test(nType) && node.parameters.responseMode === "lastNode") {
        node.parameters.responseMode = "onReceived";
        if (!node.parameters.responseData) {
          node.parameters.responseData = "noData";
        }
        patches.push(`Switched synchronous webhook '${nName}' from 'lastNode' to 'onReceived' (<5s ACK)`);
      }
    }
  }

  const aiNodes = hardened.nodes.filter((n) => /langchain|agent|openAi|anthropic|gemini/i.test(String(n.type || "")));
  const hasIf = hardened.nodes.some((n) => /n8n-nodes-base\.if$|n8n-nodes-base\.switch$/i.test(String(n.type || "")));
  if (aiNodes.length > 0 && !hasIf) {
    const primaryAi = aiNodes[0];
    const aiName = String(primaryAi.name || "AI Node");
    const guardName = "HookTriage AI Output Guard";
    const guardPos = Array.isArray(primaryAi.position)
      ? [Number(primaryAi.position[0] || 400) + 240, Number(primaryAi.position[1] || 300)]
      : [maxX + 240, maxY];

    hardened.nodes.push({
      parameters: {
        conditions: {
          options: {
            caseSensitive: true,
            leftValue: "",
            typeValidation: "loose",
          },
          conditions: [
            {
              id: "ht-ai-nonempty-guard",
              leftValue: "={{ String($json.output ?? $json.text ?? $json.content ?? JSON.stringify($json) ?? '').trim() }}",
              rightValue: "",
              operator: {
                type: "string",
                operation: "notEmpty",
              },
            },
          ],
          combinator: "and",
        },
        options: {},
      },
      id: `ht-guard-${crypto.randomBytes(4).toString("hex")}`,
      name: guardName,
      type: "n8n-nodes-base.if",
      typeVersion: 2,
      position: guardPos,
    });

    const prevAiMain = hardened.connections[aiName]?.main || [];
    hardened.connections[aiName] = {
      ...(hardened.connections[aiName] || {}),
      main: [[{ node: guardName, type: "main", index: 0 }]],
    };
    hardened.connections[guardName] = {
      main: [prevAiMain[0] || [], []],
    };
    patches.push(`Inserted '${guardName}' (IF non-empty output validation) after '${aiName}'`);
  }

  const dlqNodeName = "HookTriage Zero-Trust PII Scrubber & DLQ";
  if (errorBranchSources.length > 0 && !hardened.nodes.some((n) => n.name === dlqNodeName)) {
    hardened.nodes.push({
      parameters: {
        jsCode:
          "const redact = (v) => String(v || '')" +
          ".replace(/\\b(sk_live_|sk_test_|sk-|re_|ghp_|gho_|whsec_|xox[baprs]-|AIza)[A-Za-z0-9_\\/+=-]{10,}\\b/g, '[REDACTED_KEY]')" +
          ".replace(/\\beyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9_-]{6,}\\b/g, '[REDACTED_JWT]')" +
          ".replace(/(Bearer\\s+)[A-Za-z0-9._-]{12,}/gi, '$1[REDACTED_TOKEN]')" +
          ".replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}/g, '[REDACTED_EMAIL]');\n" +
          "return $input.all().map((item) => ({\n" +
          "  json: {\n" +
          "    dlq: true,\n" +
          "    scrubbed_at: new Date().toISOString(),\n" +
          "    error: redact(item.json?.error?.message || item.json?.message || 'Downstream node failure'),\n" +
          "    payload_preview: redact(JSON.stringify(item.json)).slice(0, 800)\n" +
          "  }\n" +
          "}));",
      },
      id: `ht-dlq-${crypto.randomBytes(4).toString("hex")}`,
      name: dlqNodeName,
      type: "n8n-nodes-base.code",
      typeVersion: 2,
      position: [maxX + 240, maxY + 220],
    });

    for (const srcName of errorBranchSources) {
      hardened.connections[srcName] = hardened.connections[srcName] || {};
      const existingMain = hardened.connections[srcName].main || [];
      if (existingMain.length < 2) {
        while (existingMain.length < 2) existingMain.push([]);
        existingMain[1] = [{ node: dlqNodeName, type: "main", index: 0 }];
        hardened.connections[srcName].main = existingMain;
      }
    }
    patches.push(`Added '${dlqNodeName}' wired to ${errorBranchSources.length} error output branch(es)`);
  }

  if (!hardened.nodes.some((n) => n.name === "HookTriage Hardening Notes")) {
    hardened.nodes.push({
      parameters: {
        content:
          "## 🛡️ Hardened by HookTriage Pro CLI\n" +
          "- **Error Workflow:** `hooktriage-watchdog-error-handler`\n" +
          "- **Retries:** `retryOnFail: true`, `maxTries: 3`, `waitBetweenTries: 2000ms`\n" +
          "- **Timeouts:** `15000ms` on external API/LLM HTTP requests\n" +
          "- **Zero-Trust DLQ:** Redacts secrets/PII before dead-letter alerting\n" +
          "- **Docs:** https://hooktriage.com/kit",
        height: 220,
        width: 420,
        color: 4,
      },
      id: `ht-note-${crypto.randomBytes(4).toString("hex")}`,
      name: "HookTriage Hardening Notes",
      type: "n8n-nodes-base.stickyNote",
      typeVersion: 1,
      position: [120, 40],
    });
    patches.push("Added 'HookTriage Hardening Notes' sticky note");
  }

  return { hardened, patches };
}

function getFlagValue(args, name) {
  const prefix = `--${name}=`;
  const eqArg = args.find((a) => a.startsWith(prefix));
  if (eqArg) return eqArg.slice(prefix.length);
  const idx = args.indexOf(`--${name}`);
  if (idx !== -1 && args[idx + 1] && !args[idx + 1].startsWith("--")) {
    return args[idx + 1];
  }
  return "";
}

function printUpsellCta(displayFile, hardenedName) {
  console.log(`\n${YELLOW}${BOLD}⚡ Auto-patch disponible : Générer ${hardenedName} (RetryOnFail, Exponential Backoff, HTTP Timeout, onError Dead-Letter, Zero-Trust PII Scrubber)${RESET}`);
  console.log(`   ${CYAN}-> Débloquer avec votre clé de licence ($27 sur ${KIT_WEB_URL}) :${RESET}`);
  console.log(`      ${BOLD}npx hooktriage fix ${displayFile} --key=HT-...${RESET}`);
  console.log(`      (ou via GitHub : npx -y github:grinem/hooktriage fix ${displayFile} --key=HT-...)`);
  console.log(`   💳 Paiement instantané CB / Apple Pay : ${KIT_STRIPE_URL}`);
}

function getHardenedOutputPath(resolvedInput, customOut) {
  if (customOut) return path.resolve(customOut);
  const parsedPath = path.parse(resolvedInput);
  const baseName = parsedPath.name.replace(/\.hardened$/i, "");
  return path.join(parsedPath.dir, `${baseName}.hardened${parsedPath.ext || ".json"}`);
}

async function runCli(args) {
  if (args.includes("--mcp")) {
    startMcpServer();
    return;
  }

  const cmd = args[0];
  const isFixCmd = cmd === "fix" || args.includes("--fix");
  const isAuditCmd = cmd === "scan" || cmd === "audit" || cmd === "fix";
  const targetFile =
    (args[1] && !args[1].startsWith("--") ? args[1] : null) ||
    args.find((a) => !a.startsWith("--") && a.endsWith(".json"));

  if (!cmd || cmd === "--help" || cmd === "-h" || (isAuditCmd && !targetFile)) {
    console.log(
      "HookTriage Zero-Trust Workflow Scanner, Auto-Hardener & MCP Server (0 bytes leave your machine)\n\n" +
      "Usage:\n" +
      "  hooktriage audit <workflow.json>                     Static audit locally (free, 0 network calls)\n" +
      "  hooktriage scan <workflow.json> [--json]             Alias for audit\n" +
      "  hooktriage fix <workflow.json> --key=HT-PRO-...      Generate <basename>.hardened.json (Pro Kit license)\n" +
      "  hooktriage audit <workflow.json> --fix --key=HT-...  Audit + auto-patch in one command\n" +
      "  hooktriage --mcp                                     Run stdio MCP server for Cursor / Claude Code / Antigravity\n\n" +
      "Pro Hardening Kit ($27) & License Keys: https://hooktriage.com/kit\n" +
      "Docs & Watchdog MIT: https://hooktriage.com | https://github.com/grinem/n8n-ai-watchdog"
    );
    process.exit(0);
  }

  const resolved = path.resolve(targetFile || cmd);
  if (!fs.existsSync(resolved)) {
    console.error(`Error: File not found: ${resolved}`);
    process.exit(1);
  }
  const raw = fs.readFileSync(resolved, "utf8");
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (e) {
    console.error(`Error parsing JSON: ${e.message}`);
    process.exit(1);
  }

  const displayFile = targetFile || path.basename(resolved);
  const outPath = getHardenedOutputPath(resolved, getFlagValue(args, "out"));
  const hardenedName = path.basename(outPath);

  const res = scanWorkflowObject(parsed);
  if (!res.ok) {
    if (args.includes("--json")) {
      console.log(JSON.stringify(res, null, 2));
    } else {
      console.error(`Error: ${res.error}`);
    }
    process.exit(1);
  }

  if (isFixCmd) {
    const providedKey = getFlagValue(args, "key");
    const license = verifyProLicenseKey(providedKey);
    if (!license.valid) {
      if (args.includes("--json")) {
        console.log(
          JSON.stringify(
            {
              ok: false,
              licensed: false,
              error: license.reason,
              findings_count: res.findings.length,
              upgrade_url: KIT_WEB_URL,
              stripe_url: KIT_STRIPE_URL,
            },
            null,
            2
          )
        );
      } else {
        console.error(`\n${RED}${BOLD}🔒 HookTriage Pro Auto-Patch Locked: ${license.reason}${RESET}`);
        if (res.findings.length > 0) {
          console.log(`\n🔍 Detected ${res.findings.length} unpatched reliability flaw(s) in ${displayFile}:`);
          res.findings.forEach((f, idx) => {
            console.log(`${RED}${idx + 1}. [${f.severity}] ${f.node} — ${f.detail}${RESET}`);
          });
        }
        printUpsellCta(displayFile, hardenedName);
        console.log("");
      }
      process.exit(1);
    }

    const { hardened, patches } = hardenWorkflowObject(parsed);
    fs.writeFileSync(outPath, JSON.stringify(hardened, null, 2) + "\n", "utf8");
    const postAudit = scanWorkflowObject(hardened);

    if (args.includes("--json")) {
      console.log(
        JSON.stringify(
          {
            ok: true,
            licensed: true,
            edition: license.edition,
            serial: license.serial,
            input_file: resolved,
            output_file: outPath,
            patches_applied: patches,
            remaining_findings: postAudit.findings.length,
          },
          null,
          2
        )
      );
      return;
    }

    console.log(`\n${GREEN}${BOLD}✅ HookTriage Pro License Verified (${license.edition} / ${license.serial}) — 100% Offline${RESET}`);
    console.log(`🛡️  Zero-Trust: 0 bytes left your machine.`);
    console.log(`🔧 Applied ${patches.length} hardening patch(es) to ${res.workflow_name}:`);
    patches.forEach((p, idx) => console.log(`   ${idx + 1}. ${p}`));
    console.log(`\n📄 Hardened workflow written to: ${BOLD}${outPath}${RESET}`);
    console.log(`🔎 Post-patch audit findings remaining: ${postAudit.findings.length}\n`);
    return;
  }

  if (args.includes("--json")) {
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  console.log(`\n🔍 HookTriage Local Audit — ${res.workflow_name} (${res.node_count} nodes)`);
  console.log(`🛡️  Zero-Trust: 0 bytes left your machine.\n`);
  if (!res.findings.length) {
    console.log(`${GREEN}✅ Baseline passed: errorWorkflow, timeouts, and retry guards look solid.${RESET}`);
  } else {
    res.findings.forEach((f, idx) => {
      const color = f.severity === "HIGH" ? RED : YELLOW;
      console.log(`${color}${idx + 1}. [${f.severity}] ${f.node} — ${f.detail}${RESET}`);
      console.log(`   Fix: ${f.fix}`);
    });
    printUpsellCta(displayFile, hardenedName);
  }
  console.log(`\n📦 Free MIT Watchdog: ${res.watchdog_template}`);
  console.log(`🌐 Interactive Triage & Post-Mortems: ${res.docs_and_remediation}\n`);
}

function startMcpServer() {
  const rl = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
  const writeMsg = (obj) => process.stdout.write(JSON.stringify(obj) + "\n");

  rl.on("line", (line) => {
    const trimmed = line.trim();
    if (!trimmed) return;
    let req;
    try {
      req = JSON.parse(trimmed);
    } catch {
      return;
    }
    const { id, method, params } = req;

    if (method === "initialize") {
      return writeMsg({
        jsonrpc: "2.0",
        id,
        result: {
          protocolVersion: "2024-11-05",
          capabilities: { tools: {} },
          serverInfo: { name: "hooktriage-local-audit", version: "1.1.0" },
        },
      });
    }
    if (method === "notifications/initialized") return;

    if (method === "tools/list") {
      return writeMsg({
        jsonrpc: "2.0",
        id,
        result: {
          tools: [
            {
              name: "scan_n8n_workflow_json",
              description: "Scans an n8n workflow JSON object or local file path completely locally (0 bytes leave machine) for silent failures, missing Error Workflow, missing HTTP timeouts, missing retries, synchronous Shopify/webhook timeouts, and unguarded AI agent loops.",
              inputSchema: {
                type: "object",
                properties: {
                  workflow_json: { type: "string", description: "Raw n8n workflow JSON string (optional if file_path provided)" },
                  file_path: { type: "string", description: "Local path to exported n8n workflow JSON file" },
                },
              },
            },
          ],
        },
      });
    }

    if (method === "tools/call" && params?.name === "scan_n8n_workflow_json") {
      try {
        let raw = params.arguments?.workflow_json || "";
        if (!raw && params.arguments?.file_path) {
          raw = fs.readFileSync(path.resolve(params.arguments.file_path), "utf8");
        }
        const parsed = JSON.parse(raw);
        const result = scanWorkflowObject(parsed);
        return writeMsg({
          jsonrpc: "2.0",
          id,
          result: { content: [{ type: "text", text: JSON.stringify(result, null, 2) }] },
        });
      } catch (err) {
        return writeMsg({
          jsonrpc: "2.0",
          id,
          result: { isError: true, content: [{ type: "text", text: `Audit error: ${err.message}` }] },
        });
      }
    }

    if (id !== undefined) {
      writeMsg({ jsonrpc: "2.0", id, error: { code: -32601, message: `Method not found: ${method}` } });
    }
  });
}

runCli(process.argv.slice(2));
