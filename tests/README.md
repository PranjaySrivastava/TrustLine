# 🧪 Tests Suite (`tests/`)

**Owners:** Shared between Pranjay, Soham, and Yajas  
**Role:** Automated Regression, Integration, and Hackathon Quality Gates  

---

## 🎯 Purpose
The `tests/` directory contains all automated test suites executed by GitHub Actions CI ([.github/workflows/pr-checks.yml](file:///c:/Users/Pranjay/Desktop/hackathon/groundtruth(nvidiaXnebius)/.github/workflows/pr-checks.yml)) before any pull request can be merged into `main`.

---

## 📁 Directory Structure & Ownership

| Subdirectory | Owner | Scope & Test Coverage |
| :--- | :--- | :--- |
| **`tests/backend/`** | **Pranjay & Soham** | • Task directory scoping rules (allowed `cwd` vs blocked `~/.ssh`).<br>• Canary secret detector across Plaintext, Hex, and Base64.<br>• Session Taint State Machine transitions.<br>• Claude Code hook stdio communication and fail-closed handling. |
| **`tests/aiml/`** | **Soham & Pranjay** | • NVIDIA Nemotron structured JSON output schema validation.<br>• Mock Nebius Token Factory inference responses.<br>• Tavily Extract markdown sanitizer tests.<br>• Tavily Search domain reputation logic.<br>• Attack suite dataset integrity. |
| **`tests/frontend/`** | **Yajas & Pranjay** | • Verification of core dashboard assets (`index.html`, `styles.css`, `app.js`).<br>• WebSocket event serialization and payload compatibility. |

---

## 🚀 Running Tests Locally

### Run All Tests:
```bash
pytest tests/ -v
```

### Run Focused Sub-Suites:
```bash
pytest tests/backend/ -v      # Backend & Gateway only
pytest tests/aiml/ -v         # AI/ML & Intelligence only
pytest tests/frontend/ -v     # Dashboard & UI only
```
