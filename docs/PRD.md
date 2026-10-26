# 📄 Product Requirements Document (PRD)

## Project Title: Agent Firewall (Guardian Gateway for Autonomous Coding Agents)
**Track:** Coding and Agentic Engineering Track (with applicability to Personal AI Track)  
**Hackathon:** Nebius x NVIDIA Global AI Hackathon (with Tavily Integration)  
**Team:** Pranjay (Lead), Soham, Yajas  
**Version:** 1.0.0  
**Date:** October 10, 2026  

---

## 1. Executive Summary & Vision

### 1.1 The Problem
Autonomous coding agents (such as Claude Code, Antigravity, OpenHands, and Cursor/Copilot CLI agents) have unprecedented access to local workstations:
* They read untrusted content from the public internet (external GitHub issues, READMEs, third-party packages, web documentation).
* They have read access to sensitive local developer assets (SSH keys, AWS/cloud credentials, `.env` files, proprietary codebase history).
* They possess external egress execution capabilities (shell commands, outbound HTTP requests, `git push`, webhook triggers).

When untrusted external content contains adversarial prompt injections, the agent can be steered to exfiltrate private credentials or run destructive commands without explicit developer consent—a scenario known in security research as the **"Lethal Trifecta"**.

### 1.2 The Solution
**Agent Firewall** is an intelligent, content-aware local security gateway and visual developer console that intercepts all tool calls between autonomous coding agents, the workstation, and the network.

Agent Firewall pairs **probabilistic AI intelligence** (powered by **NVIDIA Nemotron** via **Nebius Token Factory** and **Tavily**) with a **deterministic, fail-closed policy engine**:
1. **Advisory AI Guardrail:** NVIDIA Nemotron Nano screens inputs at sub-second speeds for prompt injections; Nemotron Super reviews borderline threats.
2. **Web Ingress Sanitizer:** Tavily Extract purifies external web content and documentation before the agent reads it, stripping invisible zero-width characters, tracking pixels, and malicious script injections.
3. **Domain Threat Intelligence:** Tavily Search vets outbound network destinations in real time to prevent communication with known exfiltration sinks (e.g. ephemeral webhooks, pastebins).
4. **Session Taint Tracking:** Tracks whether an agent has ingested untrusted content during a session; escalates all subsequent privileged actions (e.g. `git push`, file deletion, outbound requests).
5. **Deterministic Canary & Egress Blocker:** The ultimate safety net. Even if a novel prompt injection tricks the AI detector, outbound calls are deeply scanned for planted canary tokens and secret patterns (API keys, SSH keys, private tokens) in plaintext, Base64, and Hex. Secret leaks are blocked cold.

---

## 2. Target Users & Audience

1. **Software Engineers & AI Developers:** Professionals utilizing AI coding assistants in terminal or IDE environments who cannot risk leaking proprietary API keys, credentials, or private intellectual property.
2. **Enterprise Security & DevSecOps Teams:** Organizations adopting agentic developer workflows requiring zero-trust auditing, egress boundary enforcement, and deterministic guardrails.
3. **Hackathon Judges (NVIDIA, Nebius, Tavily):** Evaluators assessing real-world impact, sponsor technology utilization, robust architecture, and polished developer experience.

---

## 3. Product Goals & Success Metrics

### 3.1 Core Objectives
* **Zero Secret Leakage:** Prevent 100% of canary tokens and credential patterns from leaving the machine under prompt injection attacks.
* **Minimal Developer Friction:** Maintain benign task completion with zero interruption inside the defined project scope.
* **Low Latency Overhead:** Keep AI content screening overhead under 250ms via Nemotron Nano and static heuristics.
* **Complete Product Experience:** Deliver not just a background daemon, but an interactive, real-time developer security console.

### 3.2 Headline Quantitative Metrics (Benchmark Target)
| Metric | Without Firewall | With Agent Firewall | Target Delta |
| :--- | :--- | :--- | :--- |
| **Attack Success Rate (ASR)** | ~90% – 100% | **0%** | -100% |
| **Personal Data Leak Rate** | ~80% – 100% | **0%** | -100% |
| **False Block Rate (Benign Tasks)** | 0% | **< 3%** | Minimal DX cost |
| **P95 Gateway Latency Overhead** | N/A | **< 280ms** | Imperceptible delay |

---

## 4. Key Features & Functional Requirements

### Feature 1: PreToolUse Interception Gateway
* Intercepts agent tool execution events before they reach the OS or network.
* Supports Claude Code `PreToolUse` hook format and custom agent runtimes.
* Returns atomic verdicts: `allow`, `ask` (human confirmation needed), or `deny` (fail-closed).

### Feature 2: Dual-Tier NVIDIA Nemotron Guard (via Nebius Token Factory)
* **Tier 1 (Nemotron Nano):** Rapidly scans tool input strings (e.g. file contents being read, bash command parameters) and returns structured JSON `{is_injection, confidence, quoted_attack, reason}`.
* **Tier 2 (Nemotron Super):** Automatically escalated when Nano confidence falls within the ambiguous band (0.40 - 0.70) to prevent false positives or subtle evasions.

### Feature 3: Tavily Web Ingress & Domain Threat Intelligence
* **Sanitized Ingress:** When an agent queries web URLs, requests pass through Tavily Extract to strip malicious HTML tricks, zero-width steganography, and hidden prompt injections before the agent parses the text.
* **Egress Verification:** Outbound network destinations are dynamically checked via Tavily Search to identify disposable webhook capture services (`webhook.site`, `requestbin`, etc.) and malicious sinks.

### Feature 4: Session Taint State Machine
* Tracks agent session lifecycle:
  * `CLEAN`: Agent is working solely on local, trusted files in repository scope.
  * `TAINTED`: Agent has ingested an external, untrusted source (README, external issue, web fetch).
  * `LOCKED`: Repeated violations detected; all external egress blocked.
* Actions like `git push`, file deletion, or outbound POST escalate to human confirmation while in `TAINTED` state.

### Feature 5: Deterministic Canary & Secret Egress Blocker
* Plants synthetic canary tokens (`CANARY-FIREWALL-SECRET-XXXX`) in environment mock tests.
* Regex and entropy scanners inspect outgoing arguments for AWS keys, GitHub PATs, private keys, and canary strings across plaintext, Hex, and Base64 representations.
* Blocks exfiltration unconditionally, even if the LLM detector did not flag the input.

### Feature 6: Real-Time Developer Security Dashboard
* Live telemetry stream via WebSockets/SSE.
* Visual indicators for session taint level, Nemotron confidence score breakdown, Tavily domain vetting status, and blocked leak alerts.
* Interactive Attack Playground & Benchmark comparison tab showing live before/after protection metrics.

### Feature 7: Drop-and-Execute (Staged Payload) Defense
* **Weaponized Write Inspection:** Analyzes tool-use file writing operations (`WriteFile`, `EditFile`, bash redirection) to detect weaponized backdoors, reverse shell patterns, and outbound webhook sinks before code can be dropped to disk.
* **Script Provenance Tracking:** Dynamically registers executable scripts (`.py`, `.sh`, `.js`, `.ps1`) authored or modified by the agent while in a `TAINTED` state.
* **Execution Escalation:** Automatically intercepts any subsequent terminal execution of agent-authored scripts during a tainted session, escalating the command to explicit human approval (`ASK`).

---

## 5. Non-Functional Requirements

1. **Security (Fail-Closed Architecture):** If the Nebius API, Tavily API, or internal policy engine is unreachable, all sensitive/outbound operations default to `deny`.
2. **Performance:** Static heuristics (regex, path scoping, canary checks) execute in $< 5\text{ms}$. Nemotron Nano inference on Nebius Token Factory targeted at $< 250\text{ms}$.
3. **Reliability & Auditability:** Every tool call, rule evaluation, and decision is recorded in an immutable local JSON/SQLite audit log.
4. **Portability:** Cross-platform support (Windows/PowerShell, macOS, Linux/Bash).

---

## 6. User Personas & User Journey

### Persona: Sarah (Senior Full-Stack Engineer)
* **Scenario:** Sarah runs an autonomous coding agent to resolve a bug reported in an open-source dependency.
* **Threat:** The dependency repository has a hidden prompt injection in a documentation file instructing the agent to dump Sarah's `~/.ssh/id_rsa` to an attacker's webhook.
* **With Agent Firewall:**
  1. The agent attempts to read the poisoned doc; Tavily sanitizes the HTML, and Nemotron Nano flags the imperative injection string.
  2. The session becomes `TAINTED`.
  3. The agent attempts to read `~/.ssh/id_rsa`; the deterministic policy engine blocks it because `~/.ssh` is outside the allowed project scope.
  4. Even if the agent tries an obfuscated shell command (`cat ~/.ssh/id_rsa | base64`), the canary/secret inspector detects the private key signature and halts the command.
  5. Sarah receives an immediate visual alert on her Agent Firewall dashboard quoting the exact malicious line from the dependency doc. Zero credentials leave her laptop.
