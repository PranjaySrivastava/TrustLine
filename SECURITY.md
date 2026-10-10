# 🔒 Security Policy

## Supported Versions

Agent Firewall follows a rolling release model during active hackathon evaluation and development:

| Version | Supported          |
| ------- | ------------------ |
| 1.0.x   | :white_check_mark: |
| < 1.0   | :x:                |

---

## 🛡️ The Agent Firewall Threat Model

Agent Firewall addresses the **"Lethal Trifecta"** in autonomous AI coding agents:
1. **Untrusted Ingress:** Indirect prompt injection via public READMEs, GitHub issues, comments, or web fetches.
2. **Local Credential Access:** Unauthorized reads of sensitive local state (`~/.ssh`, `~/.aws`, `.env`).
3. **External Egress Exfiltration:** Outbound data leaks via `curl`, `git push`, webhook beacons, or markdown rendering exploits.

### Core Defense Invariants
* **Advisory AI Detection:** Prompted LLM classifiers (NVIDIA Nemotron via Nebius Token Factory) provide early detection, but are treated as probabilistic.
* **Deterministic Fail-Closed Policy:** The policy engine is the final gatekeeper. If personal data (canary strings, private keys, cloud tokens) appears in any outbound action, the action is blocked or escalated to human confirmation—**even if the LLM detector missed the attack**.
* **Session Taint Tracking:** Any ingestion of external, unverified data taints the session, enforcing human confirmation on subsequent privileged operations.

---

## 🚨 Reporting a Vulnerability

If you discover a novel evasion technique, egress bypass, or vulnerability in Agent Firewall:

1. **Do not create a public GitHub issue.**
2. Send an email to the security lead: `security@agentfirewall.dev` (or open a private security advisory on GitHub).
3. Include:
   * Attack vector description and bypass payload.
   * Target tool call (`tool_name`, `tool_input`).
   * Observed vs. expected firewall behavior.
4. We acknowledge all reports within 24 hours.
