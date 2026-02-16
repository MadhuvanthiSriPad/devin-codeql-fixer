# Devin CodeQL Fixer

> Automatically fix CodeQL security vulnerabilities using [Devin](https://devin.ai) — from alert to merged PR, fully autonomous.

A GitHub Actions pipeline that fetches open CodeQL alerts, intelligently batches them, and dispatches each batch to Devin for autonomous root-cause fixing. Each batch produces one Pull Request with tested, CI-ready security fixes.

---

## Design Principles

| # | Principle | How It Works |
|---|-----------|-------------|
| 1 | **Idempotent** | Safe to re-run any number of times. Uses content-based batch IDs (SHA-256 of alert numbers) so re-runs produce the same branch name. Checks for existing branches and open PRs before dispatching. |
| 2 | **Clear PR titles** | PR titles name the actual vulnerabilities: `fix(security): Sql Injection, Reflected Xss (alerts #3, #7, #12)` instead of generic batch numbers. |
| 3 | **Deep root-cause fixes** | Prompt explicitly forbids shallow approaches (suppression annotations, no-op validation). Demands data-flow tracing, industry-standard remediations, and explanation of why the fix is correct. |
| 4 | **CI-green PRs** | Devin is instructed to run the full test suite and linter before opening the PR, and fix any failures caused by the changes. |
| 5 | **No duplicate work** | Only `state=open` alerts are fetched. Once a fix merges and CodeQL re-scans, the alert auto-closes and is never picked up again. In-flight alerts are tracked via `<!-- codeql-alert-ids: ... -->` markers in PR bodies. |

---

## Architecture

```
┌──────────────┐      ┌────────────────────┐      ┌─────────────┐
│  CodeQL scan  │─────>│  GitHub Action      │─────>│  Devin API  │
│  (alerts)     │      │  fetch → dedup →    │      │  (sessions) │
│               │      │  batch → dispatch   │      │             │
└──────────────┘      └────────────────────┘      └──────┬──────┘
                                                         │
                                                 ┌───────▼───────┐
                                                 │  Devin clones  │
                                                 │  repo, traces  │
                                                 │  data flow,    │
                                                 │  applies fix,  │
                                                 │  runs tests,   │
                                                 │  opens PR      │
                                                 └───────────────┘
```

**Pipeline steps:**

1. **Fetch** — queries GitHub Code Scanning API for all open CodeQL alerts
2. **Deduplicate** — skips alerts that already have an open PR or active Devin branch
3. **Filter** — excludes alerts below the configured severity threshold
4. **Batch** — groups remaining alerts (default: 3 per batch) with deterministic IDs
5. **Branch check** — skips batches whose branch (`devin/codeql-fix-{hash}`) already exists
6. **Dispatch** — creates a Devin session per batch with a detailed root-cause-fix prompt
7. **Poll** — monitors each session until completion, writes a summary report
8. **PR** — Devin opens one Pull Request per batch with vulnerability analysis and fix details

---

## Quick Start

### Prerequisites

- GitHub repository with [CodeQL](https://codeql.github.com/) enabled
- A GitHub PAT with `repo` and `security_events` scopes
- A Devin API token from [devin.ai](https://devin.ai)

### Setup

1. **Clone this repo** or copy the `.github/workflows/` and `scripts/` directories into your own repo.

2. **Add repository secrets** (Settings > Secrets and variables > Actions):

   | Secret            | Description                                      |
   |-------------------|--------------------------------------------------|
   | `GH_PAT`          | GitHub PAT with `repo` + `security_events` scope |
   | `DEVIN_API_TOKEN`  | Your Devin API token                             |

3. **Push to GitHub** — the `codeql-analysis.yml` workflow runs on push and generates alerts.

4. **Trigger the fixer** — once CodeQL scanning completes:
   - Go to Actions > **Fix CodeQL Issues with Devin** > Run workflow

### Configuration

| Input             | Default    | Description                                   |
|-------------------|------------|-----------------------------------------------|
| `batch_size`      | `3`        | Alerts per Devin session / PR                 |
| `severity_filter` | `medium`   | Minimum severity: critical, high, medium, low |

---

## Vulnerable App

The repo includes a `vulnerable-app/` directory with **intentionally vulnerable** code (JavaScript + Python) that CodeQL flags. This lets you test the full end-to-end flow.

### Vulnerability Coverage

| Vulnerability         | JS (`server.js`)  | Python (`app.py`)  | CodeQL Rules                        |
|-----------------------|--------------------|--------------------|-------------------------------------|
| SQL Injection         | String concat in query | f-string in query | `js/sql-injection`, `py/sql-injection` |
| Reflected XSS         | User input in HTML | Template injection | `js/reflected-xss`, `py/reflective-xss` |
| Path Traversal        | User-controlled path | Unsanitized path  | `js/path-injection`, `py/path-injection` |
| Command Injection     | Shell interpolation | `shell=True`       | `js/command-line-injection`, `py/command-line-injection` |
| Open Redirect         | Unvalidated target | Unvalidated target | `js/server-side-unvalidated-url-redirection`, `py/url-redirection` |
| Hardcoded Credentials | Constants in source | Constants in source | `js/hardcoded-credentials`, `py/hardcoded-credentials` |

### End-to-End Test

1. Push the repo to GitHub
2. Wait for **CodeQL Analysis** workflow to complete
3. Check **Security** tab > Code scanning alerts — you should see 10+ alerts
4. Run **Fix CodeQL Issues with Devin** from Actions tab
5. Watch Devin sessions work (links appear in the Actions run summary)
6. Review the PRs Devin opens — each should have:
   - A descriptive title naming the actual vulnerabilities
   - Root cause analysis in the PR body
   - `<!-- codeql-alert-ids: ... -->` tracking marker
7. Merge a PR, wait for CodeQL re-scan — fixed alerts auto-close
8. Re-run the fixer — it skips closed alerts (idempotent)

---

## Repository Structure

```
.
├── .github/workflows/
│   ├── codeql-analysis.yml          # Scans repo for vulnerabilities
│   └── codeql-fixer.yml             # Dispatches fixes to Devin
├── scripts/
│   ├── fix_codeql_issues.py         # Core automation (fetch, dedup, batch, dispatch)
│   ├── test_fix_codeql_issues.py    # Unit tests (pytest)
│   └── requirements.txt             # Python dependencies
├── vulnerable-app/
│   ├── server.js                    # Intentionally vulnerable Express app
│   ├── app.py                       # Intentionally vulnerable Flask app
│   ├── package.json                 # Node.js dependencies
│   └── requirements.txt             # Python dependencies
├── .env.example                     # Environment variable template
├── .gitignore
└── README.md
```

---

## How Devin Fixes Vulnerabilities

The prompt sent to Devin enforces **industry-standard remediations**, not shallow workarounds:

| Vulnerability | Required Fix | Rejected Approaches |
|---------------|-------------|---------------------|
| SQL Injection | Parameterized queries | String concatenation, `escape()` wrappers |
| XSS | Context-appropriate output encoding | `innerHTML` without sanitization |
| Path Traversal | Canonical path resolution + allowlist | Regex-only filtering |
| Command Injection | Array-based exec, no shell interpolation | Blocklist of characters |
| Hardcoded Credentials | Environment variables or secret managers | Obfuscation, Base64 encoding |

Devin is explicitly instructed to:
- **Trace the data flow** from source to sink
- **Fix at the right layer** (input validation, safe APIs, or output encoding)
- **Run tests** and fix any failures caused by changes
- **Never use** suppression annotations (`// codeql-ignore`, `@SuppressWarnings`)

---

## Enterprise Value

| Benefit | Description |
|---------|-------------|
| **Automated remediation** | Security alerts get fixed in hours, not sprints |
| **Developer time saved** | Engineers review focused PRs instead of writing fixes from scratch |
| **Continuous compliance** | Scheduled weekly runs catch new alerts as they appear |
| **Audit trail** | Every fix has a PR with root cause analysis linking back to the alert |
| **Safe to automate** | Idempotent design means accidental re-runs cause zero harm |

---
