<p align="center">
  <img src="assets/hooktriage_logo_512.png" alt="HookTriage Logo" width="96" />
</p>

# HookTriage CLI & Zero-Trust MCP Server

Audit n8n workflows, Shopify/Stripe webhook configs, and AI Agent pipelines **directly inside your terminal or AI IDE (Cursor, Claude Code, Antigravity, Windsurf)** with **0 bytes uploaded**.

---

## ⚡ Instant Usage (Zero Install)

```bash
npx -y github:grinem/hooktriage scan ./my-workflow.json
```

JSON output for CI checks:

```bash
npx -y github:grinem/hooktriage scan ./my-workflow.json --json
```

---

## 🤖 Use as an MCP Server in Cursor / Claude Code / Antigravity

Add this to your MCP configuration (`mcp.json` / `.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "hooktriage": {
      "command": "npx",
      "args": ["-y", "github:grinem/hooktriage", "--mcp"]
    }
  }
}
```

Exposes the local read-only tool **`scan_n8n_workflow_json`** which detects:
- Missing `settings.errorWorkflow` (silent runtime drops)
- External API/LLM nodes missing `options.timeout`
- Missing `retryOnFail` on HTTP `429` / `502` boundaries
- Synchronous webhook responders violating 5s upstream cutoffs (Shopify/Stripe)
- AI Agent nodes returning empty `[]` / broken JSON without downstream IF guards

---


## 🧩 1-Click AI Agent Skill (Claude Code, Cursor, Copilot, 20+ Agents)

Install the verified, security-scanned **HookTriage** skill directly into your AI coding agent via Agensi (Free):

- **[Install HookTriage Skill on Agensi (Free)](https://www.agensi.io/r/HOOKTRIAGE?to=/skills/hooktriage-n8n-webhook-silent-failure-auditor&utm_source=github)**

---


## 📸 Before vs. After (Real Local Audit & Hardened Blueprint)

![HookTriage CLI Before and After](assets/01_hooktriage_cli_before_after.png)

![Shopify Order Webhook Guard Blueprint](assets/02_shopify_hardened_workflow_blueprint.png)

## 🚀 Skip Manual Hardening — HookTriage Pro Kit ($27 One-Time)

Get **4 ready-to-import hardened n8n v1.x JSON blueprints** (HMAC-SHA256 verification, `<5s` Shopify ACK, `300s` Stripe replay protection, 24h idempotency, AI Agent circuit breaker & Dead-Letter Queue):

- **[Buy Pro Kit ($27 — Instant Card / Stripe via Agensi)](https://www.agensi.io/r/HOOKTRIAGE?to=/skills/hooktriage-n8n-production-hardening-kit&utm_source=github)**
- **[Or Pay via Crypto / Direct Download on hooktriage.com](https://hooktriage.com/#hardening-kit)**

---

## 🔗 Companion Resources

- **Live Knowledge Base & Web Pre-Scanner**: [https://hooktriage.com](https://hooktriage.com)
- **Zero-Trust n8n Watchdog Template (MIT)**: [`grinem/n8n-ai-watchdog`](https://github.com/grinem/n8n-ai-watchdog)
- **Contact / Support**: `ops@hooktriage.com`

## 📄 License

MIT
