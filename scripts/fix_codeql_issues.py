"""
Devin CodeQL Fixer
==================
Fetches open CodeQL security alerts from a GitHub repository,
deduplicates against in-flight work, groups into batches, and creates
a Devin session per batch. Devin fixes root causes and opens PRs.

Key design goals:
  1. Idempotent   — safe to re-run; skips alerts already being worked on
  2. Clear PRs    — titles name the actual vulnerabilities, not batch numbers
  3. Deep fixes   — prompt demands root-cause fixes, not shallow suppression
  4. CI-green PRs — Devin must run tests + linting before opening the PR
  5. No duplicates on merge — only open alerts are processed; once a fix
     merges and CodeQL re-scans, the alert auto-closes and is never picked
     up again

Usage:
    GITHUB_TOKEN, DEVIN_API_TOKEN, GITHUB_REPOSITORY,
    BATCH_SIZE (default 3), SEVERITY_FILTER (default "medium")

    python fix_codeql_issues.py
"""

import hashlib
import os
import sys
import json
import time
import logging
import requests

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

GITHUB_API = "https://api.github.com"
DEVIN_API = "https://api.devin.ai/v1"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "warning", "note"]

# Prefix used on all Devin-created branches so we can detect in-flight work
BRANCH_PREFIX = "devin/codeql-fix"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def env(name: str, default: str | None = None) -> str:
    """Return an environment variable or exit with a clear message."""
    value = os.environ.get(name, default)
    if value is None:
        log.error("Missing required environment variable: %s", name)
        sys.exit(1)
    return value


def validate_github_token(token: str) -> None:
    """Validate the GitHub token by calling GET /user. Exit on failure."""
    if not token or not token.strip():
        log.error(
            "GITHUB_TOKEN is empty. Provide a valid GitHub Personal Access "
            "Token with 'repo' and 'security_events' scopes."
        )
        sys.exit(1)
    try:
        resp = requests.get(
            f"{GITHUB_API}/user",
            headers=github_headers(token),
            timeout=15,
        )
    except requests.RequestException as exc:
        log.error("Failed to connect to GitHub API: %s", exc)
        sys.exit(1)
    if resp.status_code == 401:
        log.error(
            "GITHUB_TOKEN is invalid or expired (HTTP 401). "
            "Generate a new token at https://github.com/settings/tokens "
            "with 'repo' and 'security_events' scopes."
        )
        sys.exit(1)
    if resp.status_code == 403:
        log.error(
            "GITHUB_TOKEN lacks required permissions (HTTP 403). "
            "Ensure the token has 'repo' and 'security_events' scopes."
        )
        sys.exit(1)
    if resp.status_code != 200:
        log.error(
            "Unexpected response from GitHub API (HTTP %d). "
            "Verify your GITHUB_TOKEN is correct.",
            resp.status_code,
        )
        sys.exit(1)
    user = resp.json().get("login", "unknown")
    log.info("GitHub token validated — authenticated as '%s'", user)


def validate_devin_token(token: str) -> None:
    """Validate the Devin API token by calling GET /sessions. Exit on failure."""
    if not token or not token.strip():
        log.error(
            "DEVIN_API_TOKEN is empty. Provide a valid Devin API token "
            "from https://app.devin.ai/settings."
        )
        sys.exit(1)
    try:
        resp = requests.get(
            f"{DEVIN_API}/sessions",
            headers=devin_headers(token),
            params={"limit": 1},
            timeout=15,
        )
    except requests.RequestException as exc:
        log.error("Failed to connect to Devin API: %s", exc)
        sys.exit(1)
    if resp.status_code in (401, 403):
        log.error(
            "DEVIN_API_TOKEN is invalid or expired (HTTP %d). "
            "Generate a new token at https://app.devin.ai/settings.",
            resp.status_code,
        )
        sys.exit(1)
    if resp.status_code >= 400:
        log.error(
            "Unexpected response from Devin API (HTTP %d). "
            "Verify your DEVIN_API_TOKEN is correct.",
            resp.status_code,
        )
        sys.exit(1)
    log.info("Devin API token validated successfully")


def severity_meets_threshold(alert_severity: str, threshold: str) -> bool:
    """Return True if *alert_severity* is >= *threshold* in priority."""
    try:
        alert_idx = SEVERITY_ORDER.index(alert_severity.lower())
    except ValueError:
        return True  # unknown severity -> include it to be safe
    try:
        threshold_idx = SEVERITY_ORDER.index(threshold.lower())
    except ValueError:
        threshold_idx = SEVERITY_ORDER.index("medium")
    return alert_idx <= threshold_idx


def stable_batch_id(alert_numbers: list[int]) -> str:
    """
    Deterministic short hash from a sorted list of alert numbers.
    Re-running with the same alerts produces the same batch ID,
    which makes the branch name stable -> idempotent.
    """
    key = ",".join(str(n) for n in sorted(alert_numbers))
    return hashlib.sha256(key.encode()).hexdigest()[:8]


def github_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }


def devin_headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def human_readable_rules(alerts: list[dict]) -> str:
    """Return a de-duped, comma-separated list of rule short names."""
    seen = []
    for a in alerts:
        rule_id = a.get("rule", {}).get("id", "unknown")
        # Convert rule ID to readable form: js/sql-injection -> SQL Injection
        name = (
            rule_id
            .split("/")[-1]         # drop language prefix
            .replace("-", " ")
            .title()
        )
        if name not in seen:
            seen.append(name)
    return ", ".join(seen)


# ---------------------------------------------------------------------------
# Step 1 — Fetch CodeQL alerts (only truly open ones)
# ---------------------------------------------------------------------------


def fetch_codeql_alerts(token: str, repo: str, severity_filter: str) -> list[dict]:
    """
    Fetch all open code-scanning alerts from the GitHub API.
    Paginates automatically, filters by severity.
    Only returns alerts with state=open (not dismissed, not fixed).
    """
    url = f"{GITHUB_API}/repos/{repo}/code-scanning/alerts"
    params = {"state": "open", "per_page": 100, "page": 1}
    headers = github_headers(token)

    all_alerts: list[dict] = []

    while True:
        log.info("Fetching alerts page %d ...", params["page"])
        resp = requests.get(url, headers=headers, params=params, timeout=30)

        if resp.status_code == 404:
            log.warning(
                "Code scanning not enabled or no alerts found for %s. "
                "Make sure CodeQL is configured in the repository.", repo,
            )
            return []

        resp.raise_for_status()
        page = resp.json()

        if not page:
            break

        all_alerts.extend(page)
        params["page"] += 1

    # Filter by severity threshold
    filtered = [
        a for a in all_alerts
        if severity_meets_threshold(
            a.get("rule", {}).get("security_severity_level", "")
            or a.get("rule", {}).get("severity", "warning"),
            severity_filter,
        )
    ]

    log.info(
        "Found %d open alerts total, %d meet severity >= %s",
        len(all_alerts), len(filtered), severity_filter,
    )
    return filtered


# ---------------------------------------------------------------------------
# Step 2 — Deduplicate: skip alerts that already have in-flight work
# ---------------------------------------------------------------------------


def get_inflight_alert_ids(token: str, repo: str) -> set[int]:
    """
    Scan open PRs whose branch starts with BRANCH_PREFIX.
    Parse alert IDs from the PR body (we embed them as a machine-readable
    comment) so we know which alerts are already being fixed.
    Also checks for active Devin branches without a PR yet.
    """
    headers = github_headers(token)
    inflight: set[int] = set()
    pr_branches: set[str] = set()

    # --- Check open Pull Requests ---
    pr_url = f"{GITHUB_API}/repos/{repo}/pulls"
    params: dict = {"state": "open", "per_page": 100, "page": 1}

    while True:
        resp = requests.get(pr_url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        prs = resp.json()

        if not prs:
            break

        for pr in prs:
            branch = pr.get("head", {}).get("ref", "")
            if branch.startswith(BRANCH_PREFIX):
                pr_branches.add(branch)
                body = pr.get("body", "") or ""
                # Parse the machine-readable footer we embed in PR bodies
                # Format: <!-- codeql-alert-ids: 12,15,18 -->
                marker = "<!-- codeql-alert-ids:"
                if marker in body:
                    ids_str = body.split(marker)[1].split("-->")[0].strip()
                    for id_str in ids_str.split(","):
                        id_str = id_str.strip()
                        if id_str.isdigit():
                            inflight.add(int(id_str))

                log.info(
                    "  Found in-flight PR #%d on branch %s",
                    pr.get("number"), branch,
                )

        params["page"] += 1

    # --- Check branches without PRs (Devin may still be working) ---
    branch_url = f"{GITHUB_API}/repos/{repo}/git/matching-refs/heads/{BRANCH_PREFIX}"
    resp = requests.get(branch_url, headers=headers, timeout=30)
    if resp.status_code == 200:
        refs = resp.json()
        for ref in refs:
            branch_name = ref.get("ref", "").replace("refs/heads/", "")
            if branch_name and branch_name not in pr_branches:
                log.warning(
                    "  Branch %s exists with no open PR — Devin may still be working. Skipping this batch.",
                    branch_name,
                )

    if inflight:
        log.info("Alerts already in-flight (skipping): %s", sorted(inflight))
    else:
        log.info("No in-flight work found — all open alerts are eligible")

    return inflight


def get_inflight_branch_ids(token: str, repo: str) -> set[str]:
    """
    Return the set of batch IDs that already have a branch pushed,
    even if no PR exists yet (Devin may still be working).
    """
    headers = github_headers(token)
    branch_ids: set[str] = set()

    ref_url = f"{GITHUB_API}/repos/{repo}/git/matching-refs/heads/{BRANCH_PREFIX}"
    resp = requests.get(ref_url, headers=headers, timeout=30)
    if resp.status_code == 200:
        for ref in resp.json():
            branch_name = ref.get("ref", "").replace("refs/heads/", "")
            # Branch format: devin/codeql-fix-a1b2c3d4
            suffix = branch_name.replace(f"{BRANCH_PREFIX}-", "")
            if suffix:
                branch_ids.add(suffix)

    return branch_ids


def deduplicate_alerts(
    alerts: list[dict], inflight_ids: set[int]
) -> list[dict]:
    """Remove alerts that are already being worked on."""
    before = len(alerts)
    deduped = [a for a in alerts if a.get("number") not in inflight_ids]
    skipped = before - len(deduped)
    if skipped:
        log.info("Skipped %d alert(s) already in-flight", skipped)
    return deduped


# ---------------------------------------------------------------------------
# Step 3 — Batch alerts
# ---------------------------------------------------------------------------


def batch_alerts(alerts: list[dict], batch_size: int) -> list[list[dict]]:
    """Split alerts into batches of *batch_size*."""
    batches = [
        alerts[i : i + batch_size]
        for i in range(0, len(alerts), batch_size)
    ]
    log.info("Created %d batch(es) of up to %d alerts each", len(batches), batch_size)
    return batches


# ---------------------------------------------------------------------------
# Step 4 — Build the Devin prompt (deep-fix focus)
# ---------------------------------------------------------------------------


def build_prompt(batch: list[dict], batch_id: str, repo: str) -> str:
    """
    Construct a detailed, root-cause-focused prompt.
    Tells Devin to understand the vulnerability, fix the source,
    run tests, and ensure CI will pass.
    """
    alert_descriptions = []
    alert_numbers = []

    for i, alert in enumerate(batch, 1):
        rule = alert.get("rule", {})
        location = alert.get("most_recent_instance", {}).get("location", {})
        alert_num = alert.get("number", "?")
        alert_numbers.append(str(alert_num))

        alert_descriptions.append(
            f"  Alert #{alert_num}: [{rule.get('id', 'unknown')}]\n"
            f"     Description : {rule.get('description', 'No description')}\n"
            f"     Severity    : {rule.get('security_severity_level') or rule.get('severity', 'N/A')}\n"
            f"     File        : {location.get('path', 'unknown')} "
            f"(lines {location.get('start_line', '?')}-{location.get('end_line', '?')})\n"
            f"     Message     : {alert.get('most_recent_instance', {}).get('message', {}).get('text', 'N/A')}\n"
            f"     HTML URL    : {alert.get('html_url', 'N/A')}"
        )

    alerts_block = "\n\n".join(alert_descriptions)
    rule_summary = human_readable_rules(batch)
    alert_id_csv = ", ".join(alert_numbers)
    pr_title = f"fix(security): {rule_summary} (alerts {alert_id_csv})"

    # Truncate PR title to 256 chars if needed
    if len(pr_title) > 256:
        pr_title = pr_title[:253] + "..."

    prompt = f"""You are working on the repository: https://github.com/{repo}

## Security Alerts To Fix

The following {len(batch)} CodeQL security alert(s) need to be fixed:

{alerts_block}

## CRITICAL: Root-Cause Fixing Requirements

Do NOT apply shallow fixes. For each alert you MUST:

1. **Understand the vulnerability class** — Read the CodeQL rule documentation
   to understand what the rule detects and WHY it is dangerous.

2. **Trace the data flow** — Follow the tainted data from source to sink.
   The fix must happen at the RIGHT place in the flow, typically:
   - Input validation/sanitization at the entry point
   - Using safe APIs instead of unsafe ones (e.g., parameterized queries
     instead of string concatenation for SQL)
   - Proper encoding at the output point

3. **Do NOT use these shallow approaches (these will be rejected)**:
   - Adding `// codeql-ignore` or `@SuppressWarnings` annotations
   - Wrapping code in try/catch without fixing the underlying issue
   - Adding no-op validation that doesn't actually sanitize
   - Moving code around without changing the security semantics
   - Simply adding type checks or null checks that don't address the vulnerability

4. **Apply the industry-standard fix for that vulnerability class**:
   - SQL Injection -> parameterized queries / prepared statements
   - XSS -> context-appropriate output encoding (HTML-encode, JS-encode, etc.)
   - Path Traversal -> canonical path resolution + allowlist check
   - Command Injection -> use array-based exec, avoid shell interpolation
   - Insecure Deserialization -> allowlist types, use safe alternatives
   - Hardcoded Credentials -> environment variables or secret managers
   - Prototype Pollution -> use Object.create(null) or Map, validate keys
   - Open Redirect -> allowlist of valid redirect targets

## Branch & PR Requirements

1. Clone the repository and create branch: `{BRANCH_PREFIX}-{batch_id}`
2. Make the minimal, correct fix for each alert. Do not refactor unrelated code.
3. **Run the full test suite** and fix any test failures your changes cause.
   - Look for test commands in: package.json scripts, Makefile, pyproject.toml,
     tox.ini, .github/workflows (check what CI runs), or README.
   - If no test suite exists, manually verify the fix logic is correct.
4. **Run the linter/formatter** if configured and fix any lint errors.
5. **Verify your fix actually resolves the CodeQL alert**:
   - Re-read the vulnerable code path after your change.
   - Confirm the tainted data can no longer reach the sink unsanitized.
6. Commit with a descriptive message referencing the alert, e.g.:
   "fix: use parameterized query to prevent SQL injection (alert #12)"
7. Push and open a Pull Request targeting the default branch with:
   - Title: "{pr_title}"
   - Body structure:
     ### Summary
     Brief overview of all fixes in this PR.

     ### Alert Details
     For EACH alert:
     - **Alert #N: [rule-id]**
       - Vulnerability: what was wrong
       - Root Cause: where tainted data flows from/to
       - Fix Applied: what you changed and why
       - Verification: how you confirmed it works

     ### Testing
     - Which tests were run and their results
     - Any new tests added (if applicable)

   - At the very end of the PR body, add this exact line for tracking:
     `<!-- codeql-alert-ids: {alert_id_csv} -->`

## Verification Checklist (complete ALL before opening PR)

- [ ] Each fix addresses the root cause, not just the symptom
- [ ] All existing tests pass
- [ ] No new lint/format warnings introduced
- [ ] Fix does not change the functional behavior of the application
- [ ] PR body explains the vulnerability and fix for each alert
- [ ] The tainted data flow is broken at the correct point
- [ ] No suppress/ignore annotations used as fixes"""

    return prompt


# ---------------------------------------------------------------------------
# Step 5 — Create Devin sessions
# ---------------------------------------------------------------------------


def create_devin_session(token: str, prompt: str, batch_id: str) -> dict:
    """Create a single Devin session and return its metadata."""
    url = f"{DEVIN_API}/sessions"
    headers = devin_headers(token)
    payload = {"prompt": prompt}

    log.info("Creating Devin session for batch %s ...", batch_id)
    resp = requests.post(url, headers=headers, json=payload, timeout=60)
    resp.raise_for_status()
    data = resp.json()

    session_id = data.get("session_id", "unknown")
    session_url = data.get("url", "")

    log.info("  -> Session %s created. URL: %s", session_id, session_url)

    return {
        "batch_id": batch_id,
        "session_id": session_id,
        "session_url": session_url,
        "alert_count": 0,
        "status": "created",
    }


# ---------------------------------------------------------------------------
# Step 6 — Poll session status
# ---------------------------------------------------------------------------


def poll_session(token: str, session_id: str, timeout_minutes: int = 30) -> str:
    """
    Poll the Devin session status until it completes or times out.
    Returns the final status string.
    """
    url = f"{DEVIN_API}/sessions/{session_id}"
    headers = devin_headers(token)
    deadline = time.time() + timeout_minutes * 60
    poll_interval = 30  # seconds

    while time.time() < deadline:
        try:
            resp = requests.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            status = data.get("status_enum", data.get("status", "unknown"))

            if status in ("finished", "stopped", "failed"):
                log.info("Session %s finished with status: %s", session_id, status)
                return status

            log.info(
                "Session %s status: %s — polling again in %ds",
                session_id, status, poll_interval,
            )
        except requests.RequestException as exc:
            log.warning("Polling error for session %s: %s", session_id, exc)

        time.sleep(poll_interval)

    log.warning("Session %s timed out after %d minutes", session_id, timeout_minutes)
    return "timeout"


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main() -> None:
    # ---- Read config ----
    gh_token = env("GITHUB_TOKEN")
    devin_token = env("DEVIN_API_TOKEN")
    repo = env("GITHUB_REPOSITORY")
    batch_size = int(env("BATCH_SIZE", "3"))
    severity_filter = env("SEVERITY_FILTER", "medium")

    log.info("=== Devin CodeQL Fixer ===")
    log.info("Repository      : %s", repo)
    log.info("Batch size      : %d", batch_size)
    log.info("Severity filter : >= %s", severity_filter)

    # ---- Validate API keys ----
    validate_github_token(gh_token)
    validate_devin_token(devin_token)

    # ---- Step 1: Fetch open alerts ----
    alerts = fetch_codeql_alerts(gh_token, repo, severity_filter)

    if not alerts:
        log.info("No actionable alerts found. Exiting cleanly.")
        _write_report([])
        return

    # ---- Step 2: Deduplicate against in-flight PRs ----
    inflight_ids = get_inflight_alert_ids(gh_token, repo)
    alerts = deduplicate_alerts(alerts, inflight_ids)

    if not alerts:
        log.info("All open alerts already have in-flight fixes. Nothing to do.")
        _write_report([])
        return

    # ---- Step 3: Batch ----
    batches = batch_alerts(alerts, batch_size)

    # ---- Step 3b: Skip batches that already have a branch ----
    inflight_branches = get_inflight_branch_ids(gh_token, repo)

    # ---- Step 4 & 5: Prompt + Create sessions ----
    session_records: list[dict] = []

    for batch in batches:
        alert_nums = [a.get("number", 0) for a in batch]
        batch_id = stable_batch_id(alert_nums)

        # Idempotency: skip if this exact batch already has a branch
        if batch_id in inflight_branches:
            log.info(
                "Batch %s already has branch %s-%s — skipping (idempotent)",
                batch_id, BRANCH_PREFIX, batch_id,
            )
            continue

        prompt = build_prompt(batch, batch_id, repo)
        record = create_devin_session(devin_token, prompt, batch_id)
        record["alert_count"] = len(batch)
        record["alert_ids"] = alert_nums
        record["rule_summary"] = human_readable_rules(batch)
        session_records.append(record)

        # Small delay between session creation
        if batch != batches[-1]:
            time.sleep(2)

    if not session_records:
        log.info("All batches already in-flight. Nothing new to dispatch.")
        _write_report([])
        return

    # ---- Step 6: Poll sessions ----
    log.info("Polling %d session(s) for completion ...", len(session_records))
    for record in session_records:
        status = poll_session(devin_token, record["session_id"], timeout_minutes=30)
        record["status"] = status

    # ---- Report ----
    _write_report(session_records)

    succeeded = sum(1 for r in session_records if r["status"] == "finished")
    total = len(session_records)
    log.info("=== Done. %d / %d sessions completed successfully. ===", succeeded, total)

    if succeeded < total:
        sys.exit(1)


def _write_report(records: list[dict]) -> None:
    report_path = "devin_sessions_report.json"
    with open(report_path, "w") as f:
        json.dump(
            {"sessions": records, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ")},
            f, indent=2,
        )
    log.info("Report written to %s", report_path)

    # GitHub Actions job summary
    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as f:
            f.write("## Devin CodeQL Fixer — Run Summary\n\n")
            if not records:
                f.write(
                    "No new work dispatched "
                    "(all alerts are clear or already in-flight).\n"
                )
            else:
                f.write("| Batch | Vulnerabilities | Alerts | Session | Status |\n")
                f.write("|-------|-----------------|--------|---------|--------|\n")
                for r in records:
                    url = r.get("session_url", "")
                    link = f"[Open]({url})" if url else "N/A"
                    rules = r.get("rule_summary", "")
                    ids = ", ".join(f"#{a}" for a in r.get("alert_ids", []))
                    f.write(
                        f"| `{r['batch_id']}` | {rules} | {ids} | {link} | {r['status']} |\n"
                    )


if __name__ == "__main__":
    main()
