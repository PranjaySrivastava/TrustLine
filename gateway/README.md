# 🛡️ Gateway Module (`gateway/`)

**Owner:** Pranjay (Team Lead & Cybersecurity)  
**Role:** Deterministic Policy Enforcement, Canary Egress Scanning, and Telemetry Dispatcher  

---

## 🎯 Purpose
The `gateway/` module is the core security brain and execution gatekeeper of Agent Firewall. It intercepts all tool calls coming from coding agents, applies zero-trust policy boundaries, detects secret leaks, tracks session taint state, and broadcasts real-time security events to the frontend dashboard.

---

## 📁 Files to Build in this Directory

| File | Primary Responsibility | Key Inputs / Outputs |
| :--- | :--- | :--- |
| **`policy_engine.py`** | Enforces hard task-scoping boundaries. Ensures agent can only read/write files within the active project directory (`cwd`). Hard-blocks paths like `~/.ssh/*`, `~/.aws/*`, `.env`. Implements fail-closed defaults. | **Input:** `{tool_name, tool_input, cwd, taint_level}`<br>**Output:** `Decision("allow" \| "ask" \| "deny", reason)` |
| **`canary_inspector.py`** | Scans outgoing tool arguments, commands, and commit messages for canary tokens (`CANARY-FIREWALL-SECRET-[A-Za-z0-9]+`) and API keys (AWS, GitHub PAT, Private Keys). Recursively checks **Plaintext, Hex, and Base64** encodings. | **Input:** Raw argument string or payload<br>**Output:** `{has_secret: bool, secret_type: str, match_snippet: str}` |
| **`taint_tracker.py`** | Session state machine (`CLEAN` $\to$ `TAINTED` $\to$ `LOCKED`). Escalates subsequent privileged commands (`git push`, destructive file ops, network POSTs) to human confirmation when tainted. | **Input:** Ingestion events / tool executions<br>**Output:** Current session state (`CLEAN` \| `TAINTED`) |
| **`server.py`** | FastAPI server hosting `/api/inspect`, `/api/confirm`, `/health`, and a WebSocket endpoint (`/ws`) streaming live telemetry to Yajas's dashboard. | **Port:** `8000`<br>**Protocols:** REST (HTTP) + WebSockets (`ws://` / `wss://`) |
| **`audit_logger.py`** | Immutable local audit logger recording timestamped event records to `logs/audit.jsonl`. | **Format:** JSON Lines with tamper-evident event hashes |

---

## 🤝 Module Interfaces (Contracts)

### To `intelligence/` (Soham):
Calls `intelligence.injection_detector.detect_injection(content)` when screening file reads or prompt inputs. Expects structured JSON:
```python
{"is_injection": bool, "confidence": float, "quoted_attack": str, "reason": str}
```

### To `dashboard/` (Yajas):
Broadcasts live events over WebSockets (`ws://localhost:8000/ws`):
```json
{
  "eventId": "evt_123",
  "toolName": "Bash",
  "argumentsPreview": "curl -X POST ...",
  "taintState": "TAINTED",
  "decision": "DENY",
  "ruleTriggered": "CANARY_EGRESS_RULE"
}
```

---

## 🧪 Local Validation
Run backend tests specific to this module:
```bash
pytest tests/backend/ -v
flake8 gateway/ --count --select=E9,F63,F7,F82
```
