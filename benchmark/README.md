# 📊 Benchmark Module (`benchmark/`)

**Owner:** Soham (AI/ML & System Design; with Pranjay oversight)  
**Role:** Attack Datasets, Victim Agent Simulation, and Quantitative Efficacy Evaluation  

---

## 🎯 Purpose
The `benchmark/` directory houses the evaluation harness that quantitatively proves the security efficacy of Agent Firewall for the hackathon judges. It runs a reproducible test suite comparing an unprotected baseline agent against an agent running behind Agent Firewall.

---

## 📁 Files to Build in this Directory

| File | Primary Responsibility | Key Output / Metrics |
| :--- | :--- | :--- |
| **`attack_suite.py`** | Defines **6 synthetic attack families** based on real-world incident research:<br>1. *README Injection* (fake setup steps stealing keys)<br>2. *Poisoned Skill File* (hidden exfiltration in `SKILL.md`)<br>3. *Source Comment Payload* (imperative prompts in code comments)<br>4. *Render-Based Exfil* (image/diagram URL tracking beacons)<br>5. *Split Instruction* (multi-turn issue comments)<br>6. *Hijacked Dependency* (package doc requesting POST)<br>Plus **3 benign developer tasks** (refactor, unit test, doc update). | JSON test scenario objects with planted canary tokens (`CANARY-FIREWALL-SECRET-XXXX`). |
| **`victim_agent.py`** | A lightweight victim agent powered by NVIDIA Nemotron on Nebius Token Factory that executes instructions directly. Provides a deterministic, reproducible baseline. | Step-by-step tool execution history. |
| **`runner.py`** | Orchestrates the evaluation harness: executes all scenarios against the baseline (Firewall OFF) and protected mode (Firewall ON). | Structured execution run records. |
| **`metrics_reporter.py`** | Compiles the run results into the headline hackathon metrics:<br>• **Attack Success Rate (ASR)**<br>• **Canary Data Leak Rate**<br>• **False Block Rate (Benign Tasks)**<br>• **P95 Latency Breakdown** | Formatted Markdown tables and JSON metrics for the README and dashboard. |

---

## 🚀 Running the Benchmark
```bash
python benchmark/runner.py --output benchmark_results.json
python benchmark/metrics_reporter.py --input benchmark_results.json
```

---

## 🧪 Local Validation
```bash
pytest tests/aiml/test_benchmark.py -v
flake8 benchmark/ --count --select=E9,F63,F7,F82
```
