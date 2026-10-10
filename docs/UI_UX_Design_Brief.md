# 🎨 UI/UX Design Brief

## Project Title: Agent Firewall Developer Console
**Sub-title:** Real-Time AI Agent Defense & Egress Telemetry Dashboard  
**Designer / Owner:** Yajas (Frontend & AI/ML)  
**Hackathon:** Nebius x NVIDIA Global AI Hackathon  
**Version:** 1.0.0  
**Date:** October 10, 2026  

---

## 1. Design Philosophy & Vision

The Agent Firewall dashboard must deliver a **command-center aesthetic** that feels like high-end cybersecurity software built specifically for the AI agent era. It must strike a balance between:
* **Mission-Critical Precision:** Crisp typography, sharp data visualizers, clear security status indicators, and zero fluff.
* **Modern Developer Appeal:** Deep obsidian dark mode, subtle glassmorphism, vibrant neon accents representing AI model inferences, and smooth micro-interactions.
* **Instant Clarity for Judges:** Within 5 seconds of opening the page, an evaluator must clearly see:
  1. Is the agent safe or tainted?
  2. What tool calls are currently being intercepted?
  3. Why was an attack blocked (showing the exact Nemotron analysis and Canary Egress trigger)?

---

## 2. Color Palette & Design Tokens

A tailored, high-contrast dark theme inspired by modern developer tooling (Vercel, Linear, Cloudflare Radar):

```css
:root {
  /* Surface & Backgrounds */
  --bg-primary: #090A0F;        /* Deep Space Obsidian */
  --bg-secondary: #12141C;      /* Card & Panel Base */
  --bg-tertiary: #1A1D2B;       /* Elevated Hover & Inputs */
  --border-subtle: #24293D;     /* Structural Borders */
  --border-active: #3E4668;     /* Focused / Selected Borders */

  /* Text & Typography */
  --text-primary: #F3F4F8;      /* High contrast white */
  --text-secondary: #9BA3BF;    /* Muted label silver */
  --text-muted: #5D6582;        /* Subtle timestamps & metadata */

  /* Semantic Security States */
  --color-safe: #10B981;         /* Emerald Green: Allowed / Clean Session */
  --color-safe-glow: rgba(16, 185, 129, 0.25);
  
  --color-warning: #F59E0B;      /* Amber / Goldenrod: Tainted / Pending User Prompt */
  --color-warning-glow: rgba(245, 158, 11, 0.25);

  --color-danger: #EF4444;       /* Crimson Red: Blocked / Canary Leak Stopped */
  --color-danger-glow: rgba(239, 68, 68, 0.35);

  /* Sponsor Accents */
  --brand-nvidia: #76B900;       /* NVIDIA Signature Green */
  --brand-nebius: #7B3FE4;       /* Nebius Electric Purple */
  --brand-tavily: #00A3FF;       /* Tavily Cyber Blue */

  /* UI Tokens */
  --radius-sm: 6px;
  --radius-md: 10px;
  --radius-lg: 16px;
  --shadow-card: 0 8px 32px -4px rgba(0, 0, 0, 0.5);
  --glass-blur: blur(16px);
}
```

---

## 3. Typography Hierarchy

* **Primary Interface Font:** `'Inter'`, `'Outfit'`, or system-ui (sans-serif) — clean, modern, neutral readability.
* **Monospace Font (Code & Payloads):** `'JetBrains Mono'`, `'Fira Code'`, or `'Cascadia Code'` — legible character distinctions, perfect for tool calls, regex signatures, and canary tokens.

```text
H1 (Dashboard Header): 28px / Semi-Bold / Letter-spacing -0.02em
H2 (Section Header): 20px / Medium / Letter-spacing -0.01em
H3 (Card Title): 15px / Semi-Bold / Uppercase / Letter-spacing 0.05em
Body (Main): 14px / Regular / Line-height 1.5
Captions & Labels: 12px / Medium / Muted
Code & Logs: 13px / Monospace / Line-height 1.45
```

---

## 4. Key Interface Components

### 4.1 Global Command Header (Navbar)
* **Brand Identity:** `AGENT FIREWALL` logo with a glowing live status beacon.
* **Sponsor Technology Badges:**
  * `NVIDIA Nemotron` (Active / Serving on Nebius Token Factory).
  * `Nebius Token Factory` (Active Latency: ~180ms).
  * `Tavily Shield` (Ingress Sanitizer Active).
* **Live Session Taint Bar:** Dynamic pill badge displaying current agent state (`CLEAN [0/10]`, `TAINTED [⚠️ Public Web Read]`, `LOCKED`).

### 4.2 Hero Telemetry Grid (3-Column Layout)
* **Column 1: Session Taint & Security Overview (Left, 30%)**
  * Radial Gauge showing Session Risk Index (0% to 100%).
  * Active Canary Tokens in Scope (e.g. `3 canary secrets armed`).
  * Total Events Handled: Count of `Allowed`, `User Prompted`, and `Blocked`.
* **Column 2: Live Tool Call Interceptor Feed (Center, 45%)**
  * Infinite live-scrolling event stream (via WebSockets).
  * Each item shows:
    * Tool badge (e.g. `Bash`, `ReadFile`, `WebFetch`, `GitPush`).
    * Target argument preview with highlight on suspicious tokens.
    * Decision Badge: `ALLOW` (Green), `ASK` (Amber), `DENY` (Red).
    * Click-to-inspect drawer revealing full packet analysis.
* **Column 3: AI & Threat Intelligence Inspector (Right, 25%)**
  * Real-time breakdown of the latest inspected event:
    * **Nemotron Nano Score:** Progress bar (0.0 to 1.0) with injection categorization.
    * **Quoted Attack Snippet:** Quoting the exact malicious imperative detected in README or comments.
    * **Tavily URL & Domain Intel:** Domain reputation badge (`SAFE_DEV` vs `EXFIL_SINK`).

### 4.3 Benchmark & Evaluation View (Tab 2)
* Visual comparison cards for hackathon judges:
  * **Attack Success Rate (ASR):** Side-by-side bar chart (Baseline 94% $\to$ Firewall 0%).
  * **Canary Leak Rate:** Donut chart (Baseline 85% $\to$ Firewall 0%).
  * **Performance Overhead:** Average latency breakdown (Nemotron 185ms, Static Rules 3ms, Tavily 120ms).

### 4.4 Interactive Attack Simulator (Playground Drawer)
* Allows judges to click 1-click test scenarios:
  1. `Test 1: Normal Code Refactor (Benign)` $\to$ Silently passes.
  2. `Test 2: Poisoned README Injection` $\to$ Caught by Nemotron Nano.
  3. `Test 3: Sneaky Base64 Secret Exfil` $\to$ Egress blocked by Canary Engine!
  4. `Test 4: Malicious Webhook Link` $\to$ Caught by Tavily Domain Intel.

---

## 5. Micro-Animations & Interaction States

1. **New Event Pulse:** When a tool call is intercepted, the top feed item smoothly drops in with a subtle glow border (`var(--color-safe-glow)` or `var(--color-danger-glow)`).
2. **Taint Escalation Flash:** When session state transitions from `CLEAN` to `TAINTED`, the global header pill flashes amber with an alert sound toggle.
3. **Canary Intercept Animation:** When an exfiltration attempt is blocked, the canary token in the inspected payload is highlighted in glowing red with a shield badge stamping `EGRESS INTERCEPTED`.
4. **Zero Layout Shifts:** Fixed container heights with internal virtualized scrolling for high-frequency tool call streaming.
