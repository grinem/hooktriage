---
name: hooktriage-workflow-auditor
description: Audit n8n workflow JSON exports, webhook configurations (Shopify, Stripe, Meta), and AI Agent pipelines locally for silent production failures using the zero-trust HookTriage CLI and MCP server. Use when the user asks to audit, harden, review, or debug an n8n workflow JSON, webhook timeout risk, missing retry policy, missing Error Workflow, or silent AI Agent empty output.
license: MIT
compatibility: Requires Node.js 18+ (npx) for CLI or MCP execution. Can also be applied purely as a static JSON audit checklist without running shell commands. Zero outbound network uploads during local scans.
metadata:
  author: hooktriage
  version: "1.0.0"
  homepage: "https://hooktriage.com"
  repository: "https://github.com/grinem/hooktriage"
---

# HookTriage — Zero-Trust n8n & Webhook Silent-Failure Auditor

Audit exported n8n workflow JSON files, webhook endpoints (Shopify, Stripe, Meta, Slack), and AI Agent chains for **silent production failures** that finish green or drop events without alerting operations.

## Security & Privacy Guarantees

- **100% Local Read-Only Audit:** Inspect only the workflow JSON file or pasted JSON explicitly provided by the user.
- **Zero Data Exfiltration:** Never upload workflow payloads, credentials, environment variables, or `.env` files to any external endpoint.
- **Built-In Redaction:** The HookTriage CLI/MCP automatically scrubs API keys (`sk_live_`, `sk-`, `ghp_`, `whsec_`, `AIza`), AWS keys, JWTs, Bearer tokens, and email addresses before printing findings.

## Audit Workflow

### Method 1 — Run via HookTriage MCP Server (Recommended)
Call local read-only tool `scan_n8n_workflow_json` via `npx -y github:grinem/hooktriage --mcp`.

### Method 2 — Run via Local CLI (Zero Install)
```bash
npx -y github:grinem/hooktriage scan ./path-to-workflow.json --json
```

### Method 3 — Direct Static JSON Inspection (5 Deterministic Checks)
1. `missing_error_workflow` (HIGH): No `errorTrigger` node and empty `settings.errorWorkflow`.
2. `missing_retry_on_fail` (HIGH): External integration/API/LLM node lacks `retryOnFail: true`.
3. `sync_webhook_cutoff` (HIGH): Webhook trigger uses `responseMode: "lastNode"` (Shopify 5s auto-deletion risk).
4. `missing_http_timeout` (MEDIUM): HTTP/LLM node lacks explicit `parameters.options.timeout`.
5. `unguarded_ai_output` (MEDIUM): AI Agent/LLM node has no downstream IF/Switch validation guard.

## Companion Resources
- **1-Click AI Agent Skill (Agensi — Verified & Security Scanned):** https://www.agensi.io/r/HOOKTRIAGE?to=/skills/hooktriage-n8n-webhook-silent-failure-auditor&utm_source=github
- **Zero-Trust n8n Watchdog Template (MIT):** https://github.com/grinem/n8n-ai-watchdog
- **Live Knowledge Base & Remediation:** https://hooktriage.com
