"""Unit tests for API key validation in fix_codeql_issues.py."""

import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, ".")
from fix_codeql_issues import validate_github_token, validate_devin_token


class TestValidateGitHubToken(unittest.TestCase):

    def test_empty_token_exits(self):
        with self.assertRaises(SystemExit) as cm:
            validate_github_token("")
        self.assertEqual(cm.exception.code, 1)

    def test_whitespace_token_exits(self):
        with self.assertRaises(SystemExit) as cm:
            validate_github_token("   ")
        self.assertEqual(cm.exception.code, 1)

    @patch("fix_codeql_issues.requests.get")
    def test_401_exits(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp
        with self.assertRaises(SystemExit) as cm:
            validate_github_token("bad-token")
        self.assertEqual(cm.exception.code, 1)

    @patch("fix_codeql_issues.requests.get")
    def test_403_exits(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_get.return_value = mock_resp
        with self.assertRaises(SystemExit) as cm:
            validate_github_token("limited-token")
        self.assertEqual(cm.exception.code, 1)

    @patch("fix_codeql_issues.requests.get")
    def test_unexpected_status_exits(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_get.return_value = mock_resp
        with self.assertRaises(SystemExit) as cm:
            validate_github_token("some-token")
        self.assertEqual(cm.exception.code, 1)

    @patch("fix_codeql_issues.requests.get")
    def test_network_error_exits(self, mock_get):
        import requests as req
        mock_get.side_effect = req.ConnectionError("Connection refused")
        with self.assertRaises(SystemExit) as cm:
            validate_github_token("some-token")
        self.assertEqual(cm.exception.code, 1)

    @patch("fix_codeql_issues.requests.get")
    def test_valid_token_succeeds(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"login": "testuser"}
        mock_get.return_value = mock_resp
        validate_github_token("ghp_validtoken")


class TestValidateDevinToken(unittest.TestCase):

    def test_empty_token_exits(self):
        with self.assertRaises(SystemExit) as cm:
            validate_devin_token("")
        self.assertEqual(cm.exception.code, 1)

    def test_whitespace_token_exits(self):
        with self.assertRaises(SystemExit) as cm:
            validate_devin_token("   ")
        self.assertEqual(cm.exception.code, 1)

    @patch("fix_codeql_issues.requests.get")
    def test_401_exits(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 401
        mock_get.return_value = mock_resp
        with self.assertRaises(SystemExit) as cm:
            validate_devin_token("bad-token")
        self.assertEqual(cm.exception.code, 1)

    @patch("fix_codeql_issues.requests.get")
    def test_403_exits(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 403
        mock_get.return_value = mock_resp
        with self.assertRaises(SystemExit) as cm:
            validate_devin_token("bad-token")
        self.assertEqual(cm.exception.code, 1)

    @patch("fix_codeql_issues.requests.get")
    def test_unexpected_status_exits(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_get.return_value = mock_resp
        with self.assertRaises(SystemExit) as cm:
            validate_devin_token("some-token")
        self.assertEqual(cm.exception.code, 1)

    @patch("fix_codeql_issues.requests.get")
    def test_network_error_exits(self, mock_get):
        import requests as req
        mock_get.side_effect = req.ConnectionError("Connection refused")
        with self.assertRaises(SystemExit) as cm:
            validate_devin_token("some-token")
        self.assertEqual(cm.exception.code, 1)

    @patch("fix_codeql_issues.requests.get")
    def test_valid_token_succeeds(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"sessions": []}
        mock_get.return_value = mock_resp
        validate_devin_token("valid-devin-token")


if __name__ == "__main__":
    unittest.main()
