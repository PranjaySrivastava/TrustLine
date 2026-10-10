# 🔌 Adapters Module (`adapters/`)

**Owner:** Pranjay (Team Lead & Cybersecurity)  
**Role:** Agent Interception Hooks & Demo Runtime Connectors  

---

## 🎯 Purpose
The `adapters/` directory contains the integration bridges connecting real-world autonomous coding agents to the Agent Firewall gateway. It translates proprietary agent tool-call events into the firewall's unified evaluation schema and returns actionable permission verdicts.

---

## 📁 Files to Build in this Directory

| File | Primary Responsibility | Protocol / Integration |
| :--- | :--- | :--- |
| **`claude_code_hook.py`** | Official Stdio adapter for Claude Code's `PreToolUse` hook. Reads incoming tool calls from `sys.stdin`, queries the gateway policy engine, and writes the decision JSON to `sys.stdout`. Catches all exceptions to guarantee fail-closed behavior. | **Input:** JSON on `stdin`<br>**Output:** `{hookSpecificOutput: {permissionDecision: "allow" \| "ask" \| "deny"}}` on `stdout` |
| **`standalone_agent.py`** | A standalone CLI coding agent runtime powered by NVIDIA Nemotron (via Nebius Token Factory). Used as a reproducible live demonstration harness to showcase attacks and defenses without requiring Claude Code installed. | **CLI Interface:** `python adapters/standalone_agent.py --task "Fix bug in repo"` |

---

## 🚀 How to Run the Adapters

### 1. Claude Code CLI Hook Integration:
Configure Claude Code to route pre-tool checks through the adapter:
```bash
claude --hook-pre-tool-use "python adapters/claude_code_hook.py"
```

### 2. Standalone Demo Agent Execution:
```bash
python adapters/standalone_agent.py --scenario "attacks/readme_injection.json"
```

---

## 🧪 Local Validation
```bash
pytest tests/backend/test_adapters.py -v
flake8 adapters/ --count --select=E9,F63,F7,F82
```
