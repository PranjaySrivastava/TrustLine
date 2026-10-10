# 🧠 Intelligence Module (`intelligence/`)

**Owner:** Soham (AI/ML & System Design; with Pranjay oversight)  
**Role:** Nebius Token Factory SDK, NVIDIA Nemotron Classifiers, and Tavily Security Shield  

---

## 🎯 Purpose
The `intelligence/` module powers the AI guardrail and external threat intelligence layers of Agent Firewall. It connects to **Nebius Token Factory** to run open-source **NVIDIA Nemotron** models for rapid prompt-injection classification, and integrates **Tavily** for web-content sanitization and real-time domain threat lookups.

---

## 📁 Files to Build in this Directory

| File | Primary Responsibility | APIs / Models Used |
| :--- | :--- | :--- |
| **`nebius_client.py`** | High-performance client connecting to Nebius Token Factory OpenAI-compatible API endpoint (`https://api.tokenfactory.nebius.ai/v1`). Handles authentication via `NEBIUS_API_KEY`, retries, latency telemetry, and offline mock fallbacks for testing. | • `nvidia/nemotron-nano`<br>• `nvidia/nemotron-super` |
| **`injection_detector.py`** | Implements the prompted classifier for tool arguments and ingested text. Prompts Nemotron to return structured JSON. Automatically escalates ambiguous scores (0.40 – 0.70) from Nano to Super. | **Output Schema:** `{is_injection: bool, confidence: float, quoted_attack: str, reason: str}` |
| **`tavily_shield.py`** | **Tavily Security Layer:**<br>1. **Web Ingress Sanitizer:** Calls Tavily Extract API to convert raw URLs into sanitized markdown, stripping zero-width text, hidden tracking pixels, and malicious HTML scripts.<br>2. **Egress Domain Intel:** Calls Tavily Search to check outbound domain reputation and flag disposable webhook sinks (`webhook.site`). | • Tavily Extract API<br>• Tavily Search API |

---

## 🤝 Module Interfaces (Contracts)

### To `gateway/` (Pranjay):
* Provides `async def check_content_safety(text: str) -> InjectionVerdict`
* Provides `async def sanitize_web_fetch(url: str) -> CleanMarkdownResult`
* Provides `async def check_domain_reputation(domain: str) -> DomainReputationVerdict`

### Fallback Invariant:
* If `NEBIUS_API_KEY` or `TAVILY_API_KEY` is not set or network fails, this module **MUST return fail-closed flags** (`verdict="UNVERIFIED", fail_closed=True`) so the gateway policy engine blocks risky operations.

---

## 🧪 Local Validation
Run AI/ML unit and mock tests:
```bash
pytest tests/aiml/ -v
flake8 intelligence/ --count --select=E9,F63,F7,F82
```
