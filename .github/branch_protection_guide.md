# 🔒 GitHub Branch Protection & Team Permissions Setup Guide

This guide details how **Pranjay (Team Lead)** can configure GitHub Repository Settings to enforce the team workflow rules:
1. **Direct Push to `main` is blocked for everyone EXCEPT the Team Lead (Pranjay).**
2. **All Pull Requests must pass automated CI tests.**
3. **All Pull Requests require approval from at least 1 team member (Soham or Yajas) before merging.**

---

## 🛠️ Step-by-Step GitHub Setup (Under 2 Minutes)

### Option A: Using GitHub Web UI (Recommended)

1. Open your repository on GitHub.
2. Navigate to **Settings** $\to$ **Branches** (or **Rules** $\to$ **Rulesets**).
3. Under **Branch protection rules**, click **Add branch protection rule**.
4. Set **Branch name pattern** to: `main`.

#### Configure the Protection Checkboxes:
* ✅ **Require a pull request before merging**
  * Check **Require approvals**: Set to **`1`**.
  * Check **Dismiss stale pull request approvals when new commits are pushed**.
* ✅ **Require status checks to pass before merging**
  * Check **Require branches to be up to date before merging**.
  * Search and select the status check: **`Build, Lint & Automated Tests`** (defined in our [.github/workflows/ci.yml](file:///c:/Users/Pranjay/Desktop/hackathon/groundtruth(nvidiaXnebius)/.github/workflows/ci.yml)).
* ✅ **Do not allow bypassing the above settings**
  * **LEAVE THIS UNCHECKED** (or under Rulesets, add `@Pranjay` as an explicit bypass actor).
  * *Why:* As the repository owner/administrator, leaving "Do not allow bypassing" unchecked ensures that **only you** have the administrator privilege to push directly or hotfix `main`, while all collaborators and contributors are strictly blocked from pushing to `main` directly and must open a PR.

5. Click **Create** or **Save changes**.

---

### Option B: Using Modern GitHub Rulesets (Newest UI)

1. Go to **Settings** $\to$ **Rules** $\to$ **Rulesets** $\to$ **New ruleset** $\to$ **New branch ruleset**.
2. Ruleset Name: `Protect Main Branch`.
3. Enforcement status: **Active**.
4. **Bypass list**:
   * Click **Add bypass** $\to$ Select **Repository Admin** (or your username `Pranjay`).
   * Set bypass mode: **Always**.
5. **Target branches**:
   * Click **Add target** $\to$ **Include default branch (`main`)**.
6. **Branch Rules**:
   * ✅ **Restrict pushes** (Blocks direct pushes for non-bypass users).
   * ✅ **Require a pull request before merging**:
     * Required approvals: **1**.
   * ✅ **Require status checks to pass**:
     * Add `Build, Lint & Automated Tests`.
7. Click **Save changes**.

---

## 🤝 Team Workflow Summary

```text
Collaborator (Soham / Yajas)
        │
        ├──> Creates feature branch: `git checkout -b feature/nemotron-client`
        ├──> Commits code & pushes to branch
        ├──> Opens Pull Request targeting `main`
        │
GitHub Actions (CI Gate)
        │
        ├──> Automatically runs: Linting, Secret Leak Scan, Automated Pytest
        ├──> Reports PASS ✅ or FAIL ❌
        │
Team Review
        │
        ├──> Reviewed & Approved by at least 1 team member
        │
Merge to Main
        │
        ├──> Merged into `main`
        └──> CD Workflow verifies main build and generates deployment summary
```
