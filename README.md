# Devin CodeQL Fixer

A GitHub Action that automatically identifies CodeQL security vulnerabilities, batches them, and dispatches each batch to [Devin](https://devin.ai) for autonomous root-cause fixing. Each batch produces one Pull Request with tested, CI-ready fixes.

## Design Principles

| # | Principle | How It Works |
|---|-----------|-------------|
| 1 | **Idempotent** | Safe to re-run any number of times. Uses content-based batch IDs (SHA-256 of alert numbers) so re-runs produce the same branch name. Checks for existing branches and open PRs before dispatching. |
| 2 | **Clear PR titles** | PR titles name the actual vulnerabilities: `fix(security): Sql Injection, Reflected Xss (alerts #3, #7, #12)` instead of generic batch numbers. |
| 3 | **Deep root-cause fixes** | Prompt explicitly forbids shallow approaches (suppression annotations, no-op validation). Demands data-flow tracing, industry-standard remediations, and explanation of why the fix is correct. |
| 4 | **CI-green PRs** | Devin is instructed to run the full test suite and linter before opening the PR, and fix any failures caused by the changes. |
| 5 | **No duplicate work on merge** | Only `state=open` alerts are fetched. Once a fix merges and CodeQL re-scans, the alert auto-closes and is never picked up again. In-flight alerts (with open PRs) are skipped via `<!-- codeql-alert-ids: ... -->` markers. |

## How It Works

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

1. **Fetch** — queries GitHub Code Scanning API for all open CodeQL alerts
2. **Deduplicate** — skips alerts that already have an open PR or active Devin branch (parsed from `<!-- codeql-alert-ids: ... -->` markers in PR bodies)
3. **Filter** — excludes alerts below the configured severity threshold
4. **Batch** — groups remaining alerts (default: 3 per batch), each batch gets a deterministic ID
5. **Branch check** — skips batches whose branch (`devin/codeql-fix-{hash}`) already exists
6. **Dispatch** — creates a Devin session per batch with a detailed root-cause-fix prompt
7. **Poll** — monitors each session until completion, writes a summary report
8. **PR** — Devin opens one Pull Request per batch with vulnerability analysis and fix details

## Quick Start

### Prerequisites

- CodeQL must be enabled on your repository
- A GitHub PAT with `repo` and `security_events` scopes
- A Devin API token from [devin.ai](https://devin.ai)

### Setup

1. **Clone this repo** or copy the `.github/workflows/` and `scripts/` directories into your own repo.

2. **Add repository secrets** (Settings > Secrets and variables > Actions):

   | Secret            | Description                                      |
   |-------------------|--------------------------------------------------|
   | `GH_PAT`          | GitHub PAT with `repo` + `security_events` scope |
   | `DEVIN_API_TOKEN`  | Your Devin API token                             |

3. **Push to GitHub** — the `codeql-analysis.yml` workflow will run on push and generate alerts from the included `vulnerable-app/`.

4. **Wait for CodeQL scan to complete** (check Actions tab), then trigger the fixer:
   - Actions > "Fix CodeQL Issues with Devin" > Run workflow

### Configuration

| Input             | Default    | Description                              |
|-------------------|------------|------------------------------------------|
| `batch_size`      | `3`        | Alerts per Devin session / PR            |
| `severity_filter` | `medium`   | Minimum severity: critical, high, medium, low |

## Testing the Full Flow

The repo includes a `vulnerable-app/` directory with intentionally vulnerable code (JS + Python) that CodeQL will flag:

| Vulnerability | JS file | Python file | CodeQL Rule |
|--------------|---------|-------------|-------------|
| SQL Injection | `server.js` | `app.py` | `js/sql-injection`, `py/sql-injection` |
| Reflected XSS | `server.js` | `app.py` | `js/reflected-xss`, `py/reflective-xss` |
| Path Traversal | `server.js` | `app.py` | `js/path-injection`, `py/path-injection` |
| Command Injection | `server.js` | `app.py` | `js/command-line-injection`, `py/command-line-injection` |
| Open Redirect | `server.js` | `app.py` | `js/server-side-unvalidated-url-redirection`, `py/url-redirection` |
| Hardcoded Credentials | `server.js` | `app.py` | `js/hardcoded-credentials`, `py/hardcoded-credentials` |

**Testing steps:**

1. Push the repo to GitHub
2. Wait for "CodeQL Analysis" workflow to complete (~5 min)
3. Check Security tab > Code scanning alerts — you should see 10+ alerts
4. Run "Fix CodeQL Issues with Devin" from Actions tab
5. Watch Devin sessions work (links in the Actions run summary)
6. Review the PRs that Devin opens — each should have:
   - A descriptive title naming the actual vulnerabilities
   - Root cause analysis in the body
   - `<!-- codeql-alert-ids: ... -->` tracking marker
7. Merge a PR, wait for CodeQL to re-scan — the fixed alerts should auto-close
8. Re-run the fixer — it should skip the now-closed alerts (idempotent)

## Repository Structure

```
.
├── .github/workflows/
│   ├── codeql-analysis.yml       # Scans repo for vulnerabilities
│   └── codeql-fixer.yml          # Dispatches fixes to Devin
├── scripts/
│   ├── fix_codeql_issues.py      # Core automation (fetch, dedup, batch, dispatch)
│   └── requirements.txt
├── vulnerable-app/
│   ├── server.js                 # Intentionally vulnerable Express app
│   ├── app.py                    # Intentionally vulnerable Flask app
│   └── package.json
├── .env.example
├── .gitignore
└── README.md
```

## Enterprise Value

For engineering organizations managing large codebases:

- **Automated remediation** — security alerts get fixed in hours, not sprints
- **Developer time saved** — engineers review focused PRs instead of writing fixes from scratch
- **Continuous compliance** — scheduled runs catch new alerts as they appear
- **Audit trail** — every fix has a PR with root cause analysis linking back to the alert
- **Safe to automate** — idempotent design means accidental re-runs cause zero harm

## License

MIT
