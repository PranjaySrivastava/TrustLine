# 🤝 Team Contributing & Zero-Conflict Git Guidelines

Welcome to the **Agent Firewall** hackathon project! To move rapidly as a team of three without stepping on each other's toes or dealing with merge conflicts, follow these guidelines.

---

## 🌳 1. Branch Naming Conventions

Never work directly on `main`. Always create a descriptive branch:
* `feature/gateway-canary-inspector` (Pranjay)
* `feature/nebius-nemotron-client` (Soham)
* `feature/dashboard-live-feed` (Yajas)
* `fix/tavily-url-sanitizer`
* `docs/hackathon-submission-notes`

---

## 🛡️ 2. The Golden Rule: Directory Isolation

Stick strictly to your module ownership as defined in [.github/CODEOWNERS](file:///c:/Users/Pranjay/Desktop/hackathon/groundtruth(nvidiaXnebius)/.github/CODEOWNERS):
* **Pranjay:** `gateway/`, `adapters/`, `.github/`
* **Soham:** `intelligence/`, `benchmark/`, `tests/aiml/`
* **Yajas:** `dashboard/`, `tests/frontend/`

> **Need changes in another teammate's folder?** Mention them in the team chat or open an issue rather than modifying their files directly.

---

## ⚡ 3. The 3-Step Routine to Avoid Merge Conflicts

Before starting work each day or pushing a branch:

### Step 1: Sync your local `main`
```bash
git checkout main
git pull origin main
```

### Step 2: Rebase your feature branch onto the latest `main`
```bash
git checkout feature/your-branch-name
git rebase main
```
*If Git reports a conflict during rebase, resolve it immediately on your local machine, run `git add .`, then `git rebase --continue`.*

### Step 3: Push to GitHub & Open a PR
```bash
git push origin feature/your-branch-name --force-with-lease
```

---

## 📝 4. Pull Request Review & Merge Protocol

1. **Keep PRs small:** Target under 150 lines of code. Small PRs merge in minutes; large PRs create conflicts.
2. **Auto-Review Assignment:** GitHub will automatically assign 1 teammate to review your PR.
3. **Automated CI Gate:** All checks in [.github/workflows/pr-checks.yml](file:///c:/Users/Pranjay/Desktop/hackathon/groundtruth(nvidiaXnebius)/.github/workflows/pr-checks.yml) must turn green (Secret scan, Flake8, Pytest).
4. **Squash and Merge:** When approved, the PR author uses **"Squash and merge"** to keep the commit history linear and conflict-free.

---

## 🧪 5. Local Testing Before Opening a PR

Always run tests locally before pushing:
```bash
pytest tests/ -v
flake8 gateway adapters intelligence benchmark tests --count --select=E9,F63,F7,F82
```
