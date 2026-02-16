"""Unit tests for fix_codeql_issues.py"""

import json
import os
import hashlib
from unittest.mock import patch, MagicMock

import pytest

from fix_codeql_issues import (
    severity_meets_threshold,
    stable_batch_id,
    human_readable_rules,
    build_prompt,
    fetch_codeql_alerts,
    get_inflight_alert_ids,
    BRANCH_PREFIX,
)


# ---------------------------------------------------------------------------
# severity_meets_threshold
# ---------------------------------------------------------------------------

class TestSeverityMeetsThreshold:
    def test_critical_meets_critical(self):
        assert severity_meets_threshold("critical", "critical") is True

    def test_high_meets_medium(self):
        assert severity_meets_threshold("high", "medium") is True

    def test_low_does_not_meet_high(self):
        assert severity_meets_threshold("low", "high") is False

    def test_medium_meets_medium(self):
        assert severity_meets_threshold("medium", "medium") is True

    def test_note_does_not_meet_low(self):
        assert severity_meets_threshold("note", "low") is False

    def test_unknown_severity_defaults_to_included(self):
        assert severity_meets_threshold("banana", "critical") is True

    def test_unknown_threshold_defaults_to_medium(self):
        assert severity_meets_threshold("high", "banana") is True
        assert severity_meets_threshold("low", "banana") is False

    def test_case_insensitive(self):
        assert severity_meets_threshold("HIGH", "medium") is True
        assert severity_meets_threshold("Low", "HIGH") is False


# ---------------------------------------------------------------------------
# stable_batch_id
# ---------------------------------------------------------------------------

class TestStableBatchId:
    def test_deterministic(self):
        id1 = stable_batch_id([3, 7, 12])
        id2 = stable_batch_id([3, 7, 12])
        assert id1 == id2

    def test_order_independent(self):
        assert stable_batch_id([12, 3, 7]) == stable_batch_id([3, 7, 12])

    def test_length_is_8_hex(self):
        result = stable_batch_id([1])
        assert len(result) == 8
        int(result, 16)  # should not raise

    def test_different_inputs_different_ids(self):
        assert stable_batch_id([1, 2]) != stable_batch_id([1, 3])

    def test_known_value(self):
        key = ",".join(str(n) for n in sorted([1, 2, 3]))
        expected = hashlib.sha256(key.encode()).hexdigest()[:8]
        assert stable_batch_id([1, 2, 3]) == expected

    def test_single_alert(self):
        result = stable_batch_id([42])
        assert isinstance(result, str)
        assert len(result) == 8


# ---------------------------------------------------------------------------
# human_readable_rules
# ---------------------------------------------------------------------------

class TestHumanReadableRules:
    def test_single_rule(self):
        alerts = [{"rule": {"id": "js/sql-injection"}}]
        assert human_readable_rules(alerts) == "Sql Injection"

    def test_deduplicates(self):
        alerts = [
            {"rule": {"id": "js/sql-injection"}},
            {"rule": {"id": "py/sql-injection"}},
        ]
        assert human_readable_rules(alerts) == "Sql Injection"

    def test_multiple_distinct_rules(self):
        alerts = [
            {"rule": {"id": "js/sql-injection"}},
            {"rule": {"id": "js/reflected-xss"}},
        ]
        result = human_readable_rules(alerts)
        assert "Sql Injection" in result
        assert "Reflected Xss" in result

    def test_preserves_insertion_order(self):
        alerts = [
            {"rule": {"id": "js/reflected-xss"}},
            {"rule": {"id": "js/sql-injection"}},
        ]
        result = human_readable_rules(alerts)
        assert result == "Reflected Xss, Sql Injection"

    def test_missing_rule_uses_unknown(self):
        alerts = [{}]
        assert human_readable_rules(alerts) == "Unknown"

    def test_empty_alerts(self):
        assert human_readable_rules([]) == ""


# ---------------------------------------------------------------------------
# build_prompt
# ---------------------------------------------------------------------------

class TestBuildPrompt:
    @pytest.fixture()
    def sample_batch(self):
        return [
            {
                "number": 4,
                "rule": {
                    "id": "js/sql-injection",
                    "description": "SQL Injection",
                    "security_severity_level": "high",
                },
                "most_recent_instance": {
                    "location": {
                        "path": "server.js",
                        "start_line": 10,
                        "end_line": 12,
                    },
                    "message": {"text": "Tainted data flows to query"},
                },
                "html_url": "https://github.com/org/repo/security/alerts/4",
            }
        ]

    def test_contains_repo_url(self, sample_batch):
        prompt = build_prompt(sample_batch, "abc12345", "org/repo")
        assert "https://github.com/org/repo" in prompt

    def test_contains_branch_name(self, sample_batch):
        prompt = build_prompt(sample_batch, "abc12345", "org/repo")
        assert f"{BRANCH_PREFIX}-abc12345" in prompt

    def test_contains_alert_details(self, sample_batch):
        prompt = build_prompt(sample_batch, "abc12345", "org/repo")
        assert "Alert #4" in prompt
        assert "js/sql-injection" in prompt
        assert "server.js" in prompt

    def test_contains_fix_rules_table(self, sample_batch):
        prompt = build_prompt(sample_batch, "abc12345", "org/repo")
        assert "Parameterized queries" in prompt
        assert "Rejected patterns" in prompt

    def test_contains_tracking_marker(self, sample_batch):
        prompt = build_prompt(sample_batch, "abc12345", "org/repo")
        assert "<!-- codeql-alert-ids: 4 -->" in prompt

    def test_pr_title_truncation(self):
        alerts = [
            {
                "number": i,
                "rule": {"id": f"js/very-long-rule-name-{i}"},
                "most_recent_instance": {
                    "location": {"path": "f.js", "start_line": 1, "end_line": 1},
                    "message": {"text": "x"},
                },
                "html_url": "",
            }
            for i in range(50)
        ]
        prompt = build_prompt(alerts, "abc", "org/repo")
        # The title in the prompt should not exceed 256 chars
        for line in prompt.splitlines():
            if line.strip().startswith("- Title:"):
                title = line.split("`")[1]
                assert len(title) <= 256


# ---------------------------------------------------------------------------
# fetch_codeql_alerts (mocked HTTP)
# ---------------------------------------------------------------------------

class TestFetchCodeqlAlerts:
    @patch("fix_codeql_issues.http")
    def test_returns_filtered_alerts(self, mock_http):
        page1 = [
            {"number": 1, "rule": {"security_severity_level": "high"}},
            {"number": 2, "rule": {"security_severity_level": "low"}},
        ]
        empty = []
        mock_resp_1 = MagicMock(status_code=200)
        mock_resp_1.json.return_value = page1
        mock_resp_2 = MagicMock(status_code=200)
        mock_resp_2.json.return_value = empty
        mock_http.get.side_effect = [mock_resp_1, mock_resp_2]

        result = fetch_codeql_alerts("tok", "org/repo", "medium")
        assert len(result) == 1
        assert result[0]["number"] == 1

    @patch("fix_codeql_issues.http")
    def test_returns_empty_on_404(self, mock_http):
        mock_resp = MagicMock(status_code=404)
        mock_http.get.return_value = mock_resp

        result = fetch_codeql_alerts("tok", "org/repo", "medium")
        assert result == []


# ---------------------------------------------------------------------------
# get_inflight_alert_ids (mocked HTTP)
# ---------------------------------------------------------------------------

class TestGetInflightAlertIds:
    @patch("fix_codeql_issues.http")
    def test_parses_alert_ids_from_pr_body(self, mock_http):
        prs = [
            {
                "number": 10,
                "head": {"ref": "devin/codeql-fix-abc123"},
                "body": "Some text\n<!-- codeql-alert-ids: 3, 7, 12 -->",
            }
        ]
        mock_resp_1 = MagicMock(status_code=200)
        mock_resp_1.json.return_value = prs
        mock_resp_1.raise_for_status = MagicMock()
        mock_resp_2 = MagicMock(status_code=200)
        mock_resp_2.json.return_value = []
        mock_resp_2.raise_for_status = MagicMock()
        mock_http.get.side_effect = [mock_resp_1, mock_resp_2]

        result = get_inflight_alert_ids("tok", "org/repo")
        assert result == {3, 7, 12}

    @patch("fix_codeql_issues.http")
    def test_ignores_non_devin_prs(self, mock_http):
        prs = [
            {
                "number": 5,
                "head": {"ref": "feature/something"},
                "body": "<!-- codeql-alert-ids: 1 -->",
            }
        ]
        mock_resp_1 = MagicMock(status_code=200)
        mock_resp_1.json.return_value = prs
        mock_resp_1.raise_for_status = MagicMock()
        mock_resp_2 = MagicMock(status_code=200)
        mock_resp_2.json.return_value = []
        mock_resp_2.raise_for_status = MagicMock()
        mock_http.get.side_effect = [mock_resp_1, mock_resp_2]

        result = get_inflight_alert_ids("tok", "org/repo")
        assert result == set()

    @patch("fix_codeql_issues.http")
    def test_handles_missing_body(self, mock_http):
        prs = [
            {
                "number": 10,
                "head": {"ref": "devin/codeql-fix-abc123"},
                "body": None,
            }
        ]
        mock_resp_1 = MagicMock(status_code=200)
        mock_resp_1.json.return_value = prs
        mock_resp_1.raise_for_status = MagicMock()
        mock_resp_2 = MagicMock(status_code=200)
        mock_resp_2.json.return_value = []
        mock_resp_2.raise_for_status = MagicMock()
        mock_http.get.side_effect = [mock_resp_1, mock_resp_2]

        result = get_inflight_alert_ids("tok", "org/repo")
        assert result == set()
