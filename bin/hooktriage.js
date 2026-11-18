#!/usr/bin/env node
/**
 * HookTriage CLI & Zero-Trust MCP Server (0 dependencies, 0 network calls by default)
 * Usage:
 *   npx -y github:grinem/hooktriage scan ./workflow.json
 *   npx -y github:grinem/hooktriage --mcp
 */
import fs from "node:fs";
import path from "node:path";
import readline from "node:readline";

function scrubSecrets(val) {
  return String(val || "")
    .replace(/\b(sk_live_|sk_test_|sk-|re_|ghp_|gho_|whsec_|xox[baprs]-|AIza)[A-Za-z0-9_/+=-]{10,}\b/g, "[REDACTED_KEY]")
    .replace(/\bAKIA[0-9A-Z]{16}\b/g, "[REDACTED_AWS]")
    .replace(/\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}\b/g, "[REDACTED_JWT]")
    .replace(/(Bearer\s+)[A-Za-z0-9._-]{12,}/gi, "$1[REDACTED_TOKEN]")
    .replace(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g, "[REDACTED_EMAIL]");
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

async function runCli(args) {
  if (args.includes("--mcp")) {
    startMcpServer();
    return;
  }

  const cmd = args[0];
  const targetFile = args[1] && !args[1].startsWith("--") ? args[1] : args.find((a) => a.endsWith(".json"));
  if (!cmd || cmd === "--help" || cmd === "-h" || (cmd === "scan" && !targetFile)) {
    console.log(
      "HookTriage Zero-Trust Workflow Scanner & MCP Server (0 bytes leave your machine by default)\n\n" +
      "Usage:\n" +
      "  hooktriage scan <workflow.json>          Static audit locally (0 network calls)\n" +
      "  hooktriage scan <workflow.json> --json   Output machine-readable JSON\n" +
      "  hooktriage --mcp                         Run stdio MCP server for Cursor / Claude Code / Antigravity\n\n" +
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

  const res = scanWorkflowObject(parsed);
  if (args.includes("--json")) {
    console.log(JSON.stringify(res, null, 2));
    return;
  }

  console.log(`\n🔍 HookTriage Local Audit — ${res.workflow_name} (${res.node_count} nodes)`);
  console.log(`🛡️  Zero-Trust: 0 bytes left your machine.\n`);
  if (!res.findings.length) {
    console.log("✅ Baseline passed: errorWorkflow, timeouts, and retry guards look solid.");
  } else {
    res.findings.forEach((f, idx) => {
      console.log(`${idx + 1}. [${f.severity}] ${f.node} — ${f.detail}`);
      console.log(`   Fix: ${f.fix}`);
    });
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
          serverInfo: { name: "hooktriage-local-audit", version: "1.0.0" },
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
