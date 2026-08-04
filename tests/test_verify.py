import json
import sys
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import verify


def _http_error(code):
    return urllib.error.HTTPError(url="https://example.test", code=code, msg="", hdrs=None, fp=None)


class VerifierDispatchTests(unittest.TestCase):
    def test_unsupported_type_returns_unverified_without_network_call(self):
        with patch("urllib.request.urlopen") as mock_urlopen:
            result = verify.verify_secret("Generic API Key", "not-a-real-secret")
        self.assertEqual(result, verify.UNSUPPORTED)
        mock_urlopen.assert_not_called()

    def test_known_type_dispatches_to_its_verifier(self):
        mock_verifier = MagicMock(return_value=verify.VERIFIED_LIVE)
        with patch.dict(verify.VERIFIERS, {"GitHub Token": mock_verifier}):
            result = verify.verify_secret("GitHub Token", "ghp_fake")
        mock_verifier.assert_called_once_with("ghp_fake")
        self.assertEqual(result, verify.VERIFIED_LIVE)


class GithubVerifierTests(unittest.TestCase):
    def test_200_response_is_verified_live(self):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        with patch("urllib.request.urlopen", return_value=mock_resp):
            self.assertEqual(verify.verify_github_token("ghp_fake"), verify.VERIFIED_LIVE)

    def test_401_is_verified_invalid(self):
        with patch("urllib.request.urlopen", side_effect=_http_error(401)):
            self.assertEqual(verify.verify_github_token("ghp_fake"), verify.VERIFIED_INVALID)

    def test_network_failure_is_verification_error(self):
        with patch("urllib.request.urlopen", side_effect=TimeoutError):
            self.assertEqual(verify.verify_github_token("ghp_fake"), verify.VERIFICATION_ERROR)


class SlackVerifierTests(unittest.TestCase):
    def test_ok_true_is_verified_live(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"ok": True}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        with patch("urllib.request.urlopen", return_value=mock_resp):
            self.assertEqual(verify.verify_slack_token("xoxb-fake"), verify.VERIFIED_LIVE)

    def test_ok_false_is_verified_invalid(self):
        mock_resp = MagicMock()
        mock_resp.read.return_value = json.dumps({"ok": False, "error": "invalid_auth"}).encode("utf-8")
        mock_resp.__enter__.return_value = mock_resp
        with patch("urllib.request.urlopen", return_value=mock_resp):
            self.assertEqual(verify.verify_slack_token("xoxb-fake"), verify.VERIFIED_INVALID)


class StripeVerifierTests(unittest.TestCase):
    def test_200_is_verified_live(self):
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        with patch("urllib.request.urlopen", return_value=mock_resp):
            self.assertEqual(verify.verify_stripe_key("sk_live_fake"), verify.VERIFIED_LIVE)

    def test_401_is_verified_invalid(self):
        with patch("urllib.request.urlopen", side_effect=_http_error(401)):
            self.assertEqual(verify.verify_stripe_key("sk_live_fake"), verify.VERIFIED_INVALID)


if __name__ == "__main__":
    unittest.main()
