# 📦 Modular Dependencies (`requirements/`)

**Owners:** Pranjay (Base), Soham (AI), Yajas / Shared (Dev)  
**Role:** Conflict-Free Dependency Management  

---

## 🎯 Purpose
To prevent Git merge conflicts when teammates add new packages simultaneously, all project dependencies are separated into modular files rather than a single monolithic list.

---

## 📁 File Breakdown & Ownership

| File | Owner | Purpose & Packages |
| :--- | :--- | :--- |
| **`base.txt`** | **Pranjay** | Core gateway and networking infrastructure: `fastapi`, `uvicorn`, `websockets`, `httpx`, `requests`, `pydantic`, `python-dotenv`. |
| **`ai.txt`** | **Soham** | AI & sponsor integrations: `openai` (for Nebius Token Factory endpoints) and `tavily-python` (for web ingress & domain intel). |
| **`dev.txt`** | **Shared** | Testing, formatting, and CI tools: `pytest`, `pytest-asyncio`, `flake8`, `pre-commit`. |

---

## ⚙️ How It Works
The root [requirements.txt](file:///c:/Users/Pranjay/Desktop/hackathon/groundtruth(nvidiaXnebius)/requirements.txt) references all three files:
```text
-r requirements/base.txt
-r requirements/ai.txt
-r requirements/dev.txt
```

### Installation:
```bash
pip install -r requirements.txt
```
