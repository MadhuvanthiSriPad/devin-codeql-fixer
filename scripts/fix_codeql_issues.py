"""
Fetches open CodeQL alerts from a GitHub repo, deduplicates against
in-flight work, batches them, and creates a Devin session per batch.

Env vars: GITHUB_TOKEN, DEVIN_API_TOKEN, GITHUB_REPOSITORY,
          BATCH_SIZE (default 3), SEVERITY_FILTER (default "medium")
"""

import hashlib
import os
import sys
import json
import time
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

GITHUB_API = "https://api.github.com"
DEVIN_API = "https://api.devin.ai/v1"
SEVERITY_ORDER = ["critical", "high", "medium", "low", "warning", "note"]
BRANCH_PREFIX = "devin/codeql-fix"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-8s  %(message)s",
)
log = logging.getLogger(__name__)


def env(name: str, default: str | None = None) -> str:
    value = os.environ.get(name, default)
    if value is None:
        log.error("Missing required environment variable: %s", name)
        sys.exit(1)
    return value


def severity_meets_threshold(alert_severity: str, threshold: str) -> bool:
    try:
        alert_idx = SEVERITY_ORDER.index(alert_severity.lower())
    except ValueError:
        return True
    try:
        threshold_idx = SEVERITY_ORDER.index(threshold.lower())
    except ValueError:
        threshold_idx = SEVERITY_ORDER.index("medium")
    return alert_idx <= threshold_idx


def stable_batch_id(alert_numbers: list[int]) -> str:
    """Deterministic short hash from sorted alert numbers."""
    key = ",".join(str(n) for n in sorted(alert_numbers))
    return hashlib.sha256(key.encode()).hexdigest()[:8]


def _retry_session() -> requests.Session:
    """Return a requests session with automatic retries on transient errors."""
    session = requests.Session()
    retries = Retry(
        total=3,
        backoff_factor=2,
        status_forcelist=[429, 502, 503, 504],
        allowed_methods=["GET", "POST", "DELETE"],
    )
    session.mount("https://", HTTPAdapter(max_retries=retries))
    return session

http = _retry_session()


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
    names: dict[str, None] = {}
    for a in alerts:
        rule_id = a.get("rule", {}).get("id", "unknown")
        name = rule_id.split("/")[-1].replace("-", " ").title()
        names.setdefault(name, None)
    return ", ".join(names)


def fetch_codeql_alerts(token: str, repo: str, severity_filter: str) -> list[dict]:
    """Fetch all open code-scanning alerts, paginated and filtered by severity."""
    url = f"{GITHUB_API}/repos/{repo}/code-scanning/alerts"
    params = {"state": "open", "per_page": 100, "page": 1}
    headers = github_headers(token)
    all_alerts: list[dict] = []

    while True:
        log.info("Fetching alerts page %d ...", params["page"])
        resp = http.get(url, headers=headers, params=params, timeout=30)

        if resp.status_code == 404:
            log.warning("Code scanning not enabled or no alerts for %s.", repo)
            return []

        resp.raise_for_status()
        page = resp.json()
        if not page:
            break

        all_alerts.extend(page)
        params["page"] += 1

    filtered = [
        a for a in all_alerts
        if severity_meets_threshold(
            a.get("rule", {}).get("security_severity_level", "")
            or a.get("rule", {}).get("severity", "warning"),
            severity_filter,
        )
    ]

    log.info(
        "Found %d open alerts, %d meet severity >= %s",
        len(all_alerts), len(filtered), severity_filter,
    )
    return filtered


def get_inflight_alert_ids(token: str, repo: str) -> set[int]:
    """Parse alert IDs from open PRs whose branch starts with BRANCH_PREFIX."""
    headers = github_headers(token)
    inflight: set[int] = set()

    pr_url = f"{GITHUB_API}/repos/{repo}/pulls"
    params: dict = {"state": "open", "per_page": 100, "page": 1}

    while True:
        resp = http.get(pr_url, headers=headers, params=params, timeout=30)
        resp.raise_for_status()
        prs = resp.json()
        if not prs:
            break

        for pr in prs:
            branch = pr.get("head", {}).get("ref", "")
            if not branch.startswith(BRANCH_PREFIX):
                continue

            body = pr.get("body", "") or ""
            marker = "<!-- codeql-alert-ids:"
            if marker in body:
                ids_str = body.split(marker)[1].split("-->")[0].strip()
                for id_str in ids_str.split(","):
                    id_str = id_str.strip()
                    if id_str.isdigit():
                        inflight.add(int(id_str))

            log.info("  In-flight PR #%d on branch %s", pr.get("number"), branch)

        params["page"] += 1

    if inflight:
        log.info("Alerts already in-flight (skipping): %s", sorted(inflight))
    else:
        log.info("No in-flight work found — all open alerts are eligible")

    return inflight


def get_inflight_branch_ids(token: str, repo: str) -> set[str]:
    """
    Return batch IDs to skip. Only skip branches with open or merged PRs.
    Stale branches (closed/unmerged PR or no PR) are deleted.
    """
    headers = github_headers(token)
    branch_ids: set[str] = set()
    owner = repo.split("/")[0]

    ref_url = f"{GITHUB_API}/repos/{repo}/git/matching-refs/heads/{BRANCH_PREFIX}"
    resp = http.get(ref_url, headers=headers, timeout=30)
    if resp.status_code != 200:
        return branch_ids

    expected_prefix = f"{BRANCH_PREFIX}-"
    for ref in resp.json():
        branch_name = ref.get("ref", "").replace("refs/heads/", "")
        if not branch_name.startswith(expected_prefix):
            continue
        suffix = branch_name[len(expected_prefix):]

        pr_resp = http.get(
            f"{GITHUB_API}/repos/{repo}/pulls",
            headers=headers,
            params={"head": f"{owner}:{branch_name}", "state": "all"},
            timeout=30,
        )

        prs = pr_resp.json() if pr_resp.status_code == 200 else []
        should_skip = False
        if prs:
            pr = prs[0]
            pr_num = pr.get("number")
            if pr.get("merged_at"):
                log.info("  Branch %s has merged PR #%d — skipping", branch_name, pr_num)
                should_skip = True
            elif pr.get("state") == "open":
                log.info("  Branch %s has open PR #%d — skipping", branch_name, pr_num)
                should_skip = True
            else:
                log.info("  Branch %s has closed (unmerged) PR #%d — deleting stale branch", branch_name, pr_num)
        else:
            log.info("  Branch %s has no PR — deleting stale branch", branch_name)

        if should_skip:
            branch_ids.add(suffix)
        else:
            del_resp = http.delete(
                f"{GITHUB_API}/repos/{repo}/git/refs/heads/{branch_name}",
                headers=headers,
                timeout=30,
            )
            if del_resp.status_code == 204:
                log.info("  Deleted stale branch %s", branch_name)
            else:
                log.warning("  Failed to delete branch %s (status %d)", branch_name, del_resp.status_code)

    return branch_ids


def build_prompt(batch: list[dict], batch_id: str, repo: str) -> str:
    alert_descriptions = []
    alert_numbers = []

    for alert in batch:
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
    if len(pr_title) > 256:
        pr_title = pr_title[:253] + "..."

    return f"""Repository: https://github.com/{repo}

## Alerts

Fix these {len(batch)} CodeQL alert(s):

{alerts_block}

## Fix Rules

For every alert, trace the tainted data from source to sink and apply the
industry-standard remediation:

| Vulnerability         | Required Fix                                      |
|-----------------------|---------------------------------------------------|
| SQL Injection         | Parameterized queries / prepared statements       |
| XSS                   | Context-appropriate output encoding               |
| Path Traversal        | Canonical path resolution + directory allowlist    |
| Command Injection     | Array-based exec, no shell interpolation           |
| Hardcoded Credentials | Environment variables or secret manager            |

**Rejected patterns** (PR will be closed if these are used):
- Suppress annotations (`codeql-ignore`, `@SuppressWarnings`, `noinspection`)
- Bare try/catch that swallows the vulnerability
- No-op validation that does not actually sanitize input

## Delivery

1. Branch: `{BRANCH_PREFIX}-{batch_id}`
2. One focused commit per alert. Message format:
   `fix: <what was fixed> (alert #N)`
3. Run the full test suite and linter. Fix any failures your changes introduce.
4. Verify the CodeQL alert is resolved — the fix must eliminate the flagged
   data-flow path, not just suppress it.
5. Open a PR targeting the default branch. **Do NOT merge the PR.**
   - Title: `{pr_title}`
   - Body must include:
     - Summary of changes
     - Per-alert breakdown: vulnerability class, root cause, fix applied
     - Test / linter results
   - Append this hidden marker as the last line of the body:
     `<!-- codeql-alert-ids: {alert_id_csv} -->`"""


def create_devin_session(token: str, prompt: str, batch_id: str) -> dict:
    log.info("Creating Devin session for batch %s ...", batch_id)
    resp = http.post(
        f"{DEVIN_API}/sessions",
        headers=devin_headers(token),
        json={"prompt": prompt},
        timeout=60,
    )
    if not resp.ok:
        log.error("Devin API error %d: %s", resp.status_code, resp.text)
        resp.raise_for_status()
    data = resp.json()

    session_id = data.get("session_id", "unknown")
    session_url = data.get("url", "")
    log.info("  -> Session %s created. URL: %s", session_id, session_url)

    return {
        "batch_id": batch_id,
        "session_id": session_id,
        "session_url": session_url,
        "status": "created",
    }


def poll_session(token: str, session_id: str, timeout_minutes: int = 30) -> str:
    """Poll Devin session until it completes or times out."""
    url = f"{DEVIN_API}/sessions/{session_id}"
    headers = devin_headers(token)
    deadline = time.time() + timeout_minutes * 60

    while time.time() < deadline:
        try:
            resp = http.get(url, headers=headers, timeout=30)
            resp.raise_for_status()
            data = resp.json()
            status = data.get("status_enum", data.get("status", "unknown"))

            if status in ("finished", "stopped", "failed"):
                log.info("Session %s finished with status: %s", session_id, status)
                return status

            log.info("Session %s status: %s — polling again in 30s", session_id, status)
        except requests.RequestException as exc:
            log.warning("Polling error for session %s: %s", session_id, exc)

        time.sleep(30)

    log.warning("Session %s timed out after %d minutes", session_id, timeout_minutes)
    return "timeout"


def _write_report(records: list[dict]) -> None:
    report_path = "devin_sessions_report.json"
    with open(report_path, "w") as f:
        json.dump(
            {"sessions": records, "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())},
            f, indent=2,
        )
    log.info("Report written to %s", report_path)

    summary_file = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_file:
        with open(summary_file, "a") as f:
            f.write("## Devin CodeQL Fixer — Run Summary\n\n")
            if not records:
                f.write("No new work dispatched (all alerts are clear or already in-flight).\n")
            else:
                f.write("| Batch | Vulnerabilities | Alerts | Session | Status |\n")
                f.write("|-------|-----------------|--------|---------|--------|\n")
                for r in records:
                    url = r.get("session_url", "")
                    link = f"[Open]({url})" if url else "N/A"
                    ids = ", ".join(f"#{a}" for a in r.get("alert_ids", []))
                    f.write(f"| `{r['batch_id']}` | {r.get('rule_summary', '')} | {ids} | {link} | {r['status']} |\n")


def main() -> None:
    gh_token = env("GITHUB_TOKEN")
    devin_token = env("DEVIN_API_TOKEN")
    repo = env("GITHUB_REPOSITORY")
    batch_size = int(env("BATCH_SIZE", "3"))
    severity_filter = env("SEVERITY_FILTER", "medium")

    log.info("=== Devin CodeQL Fixer ===")
    log.info("Repository: %s | Batch size: %d | Severity: >= %s", repo, batch_size, severity_filter)

    alerts = fetch_codeql_alerts(gh_token, repo, severity_filter)
    if not alerts:
        log.info("No actionable alerts found.")
        _write_report([])
        return

    inflight_ids = get_inflight_alert_ids(gh_token, repo)
    alerts = [a for a in alerts if a.get("number") not in inflight_ids]
    if not alerts:
        log.info("All open alerts already have in-flight fixes.")
        _write_report([])
        return

    batches = [alerts[i : i + batch_size] for i in range(0, len(alerts), batch_size)]
    log.info("Created %d batch(es)", len(batches))

    inflight_branches = get_inflight_branch_ids(gh_token, repo)

    session_records: list[dict] = []
    for i, batch in enumerate(batches):
        alert_nums = [a.get("number", 0) for a in batch]
        batch_id = stable_batch_id(alert_nums)

        if batch_id in inflight_branches:
            log.info("Batch %s already has active branch — skipping", batch_id)
            continue

        prompt = build_prompt(batch, batch_id, repo)
        record = create_devin_session(devin_token, prompt, batch_id)
        record["alert_count"] = len(batch)
        record["alert_ids"] = alert_nums
        record["rule_summary"] = human_readable_rules(batch)
        session_records.append(record)

        if i < len(batches) - 1:
            time.sleep(2)

    if not session_records:
        log.info("All batches already in-flight. Nothing new to dispatch.")
        _write_report([])
        return

    log.info("Polling %d session(s) concurrently ...", len(session_records))
    with ThreadPoolExecutor(max_workers=len(session_records)) as pool:
        futures = {
            pool.submit(poll_session, devin_token, r["session_id"]): r
            for r in session_records
        }
        for future in as_completed(futures):
            record = futures[future]
            record["status"] = future.result()

    _write_report(session_records)

    succeeded = sum(1 for r in session_records if r["status"] == "finished")
    log.info("=== Done. %d / %d sessions succeeded. ===", succeeded, len(session_records))

    if succeeded < len(session_records):
        sys.exit(1)


if __name__ == "__main__":
    main()
