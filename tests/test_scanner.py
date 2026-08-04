import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import (
    Finding,
    ScanResult,
    build_sarif,
    export_json,
    redact,
    sarif_rule_id,
    scan_content,
    scan_path,
    should_scan_file,
)
import verify


class ScanContentTests(unittest.TestCase):
    def test_detects_aws_access_key_id(self):
        findings = scan_content('key = "AKIAABCDEFGHIJKLMNOP"', "config.py")
        types = [f.secret_type for f in findings]
        self.assertIn("AWS Access Key ID", types)

    def test_detects_github_token(self):
        token = "ghp_" + ("a" * 36)
        findings = scan_content(f'export GITHUB_TOKEN={token}', "deploy.sh")
        types = [f.secret_type for f in findings]
        self.assertIn("GitHub Token", types)

    def test_detects_private_key_block(self):
        findings = scan_content("-----BEGIN RSA PRIVATE KEY-----", "id_rsa")
        types = [f.secret_type for f in findings]
        self.assertIn("Private Key Block", types)

    def test_detects_database_connection_string(self):
        findings = scan_content(
            'DATABASE_URL = "postgres://admin:hunter2@db.internal:5432/app"',
            "settings.py",
        )
        types = [f.secret_type for f in findings]
        self.assertIn("Database Connection String", types)

    def test_detects_stripe_secret_key(self):
        # Deliberately low-entropy placeholder (not a real-looking key) so it
        # still satisfies the pattern's character class without resembling
        # an actual credential.
        key = "sk_live_" + "x" * 24
        findings = scan_content(f'STRIPE_KEY = "{key}"', "billing.py")
        types = [f.secret_type for f in findings]
        self.assertIn("Stripe Secret Key", types)

    def test_clean_content_has_no_findings(self):
        content = (
            "def add(a, b):\n"
            "    return a + b\n\n"
            "API_KEY = os.environ.get('API_KEY')\n"
        )
        findings = scan_content(content, "clean.py")
        self.assertEqual(findings, [])

    def test_finding_records_correct_line_number(self):
        content = "line one\nline two\nAKIAABCDEFGHIJKLMNOP\nline four"
        findings = scan_content(content, "config.py")
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].line_number, 3)

    def test_matched_text_is_redacted_in_finding(self):
        findings = scan_content('key = "AKIAABCDEFGHIJKLMNOP"', "config.py")
        self.assertNotIn("AKIAABCDEFGHIJKLMNOP", findings[0].matched_text)
        self.assertIn("*", findings[0].matched_text)

    def test_verify_false_by_default_and_no_network_call(self):
        with patch("scanner.verify_secret") as mock_verify:
            findings = scan_content('key = "AKIAABCDEFGHIJKLMNOP"', "config.py")
        mock_verify.assert_not_called()
        self.assertEqual(findings[0].verification, "not-checked")

    def test_verify_true_calls_verifier_and_records_status(self):
        token = "ghp_" + ("a" * 36)
        with patch("scanner.verify_secret", return_value="verified-live") as mock_verify:
            findings = scan_content(f'export GITHUB_TOKEN={token}', "deploy.sh", verify=True)
        mock_verify.assert_called_once_with("GitHub Token", token)
        self.assertEqual(findings[0].verification, "verified-live")

    def test_verify_true_never_leaks_raw_secret_even_when_verifying(self):
        raw_secret = "SG." + ("a" * 22) + "." + ("b" * 43)
        with patch("scanner.verify_secret", return_value="verified-live"):
            findings = scan_content(f'SENDGRID_KEY = "{raw_secret}"', "mail.py", verify=True)
        self.assertNotIn(raw_secret, findings[0].matched_text)
        self.assertNotIn(raw_secret, findings[0].line_content)

    def test_verified_live_escalates_effective_severity_to_critical(self):
        raw_secret = "SG." + ("a" * 22) + "." + ("b" * 43)
        with patch("scanner.verify_secret", return_value="verified-live"):
            findings = scan_content(f'SENDGRID_KEY = "{raw_secret}"', "mail.py", verify=True)
        self.assertEqual(findings[0].severity, "HIGH")
        self.assertEqual(findings[0].effective_severity, "CRITICAL")


class RedactTests(unittest.TestCase):
    def test_short_match_is_fully_masked(self):
        self.assertEqual(redact("short", "short"), "*****")

    def test_long_match_keeps_first_and_last_four_chars(self):
        result = redact("AKIAABCDEFGHIJKLMNOP", "AKIAABCDEFGHIJKLMNOP")
        self.assertTrue(result.startswith("AKIA"))
        self.assertTrue(result.endswith("MNOP"))
        self.assertNotIn("BCDEFGHIJKL", result)

    def test_redacted_length_matches_original(self):
        match = "AKIAABCDEFGHIJKLMNOP"
        self.assertEqual(len(redact(match, match)), len(match))


class ShouldScanFileTests(unittest.TestCase):
    def test_accepts_known_extension(self):
        self.assertTrue(should_scan_file(Path("app.py")))
        self.assertTrue(should_scan_file(Path(".env")))

    def test_rejects_unknown_extension(self):
        self.assertFalse(should_scan_file(Path("photo.png")))
        self.assertFalse(should_scan_file(Path("README.md")))

    def test_rejects_lockfiles_even_with_scannable_extension(self):
        self.assertFalse(should_scan_file(Path("package-lock.json")))


class ScanPathTests(unittest.TestCase):
    def test_scans_directory_and_finds_seeded_secret(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "config.py").write_text('AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')
            (root / "notes.txt").write_text("nothing secret here\n")

            result = scan_path(str(root))

            self.assertEqual(result.files_scanned, 1)
            self.assertEqual(result.files_skipped, 1)
            self.assertEqual(result.total_findings, 1)
            self.assertEqual(result.critical_count, 1)

    def test_skips_ignored_directories(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            skipped = root / "node_modules"
            skipped.mkdir()
            (skipped / "bundled.js").write_text('AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')

            result = scan_path(str(root))

            self.assertEqual(result.total_findings, 0)

    def test_single_file_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "config.py"
            target.write_text('AWS_KEY = "AKIAABCDEFGHIJKLMNOP"\n')

            result = scan_path(str(target))

            self.assertEqual(result.files_scanned, 1)
            self.assertEqual(result.total_findings, 1)


class ScanResultTests(unittest.TestCase):
    def test_severity_counts_are_independent(self):
        result = ScanResult(target="x")
        result.findings = [
            Finding("f", 1, "", "AWS Access Key ID", "CRITICAL", "x"),
            Finding("f", 2, "", "AWS Access Key ID", "CRITICAL", "x"),
            Finding("f", 3, "", "Generic API Key", "HIGH", "x"),
        ]
        self.assertEqual(result.total_findings, 3)
        self.assertEqual(result.critical_count, 2)
        self.assertEqual(result.high_count, 1)

    def test_summary_fields_support_report_viewer(self):
        result = ScanResult(target=".")
        result.findings = [
            Finding("f", 1, "x", "AWS Access Key ID", "CRITICAL", "AKIA************MNOP"),
            Finding("f", 2, "x", "GitHub Token", "CRITICAL", "ghp_********************************aaaa"),
            Finding("f", 3, "x", "Generic API Key", "HIGH", "api_************1234"),
        ]

        self.assertEqual(result.risk_level, "CRITICAL")
        self.assertEqual(result.severity_counts["CRITICAL"], 2)
        self.assertEqual(result.secret_type_counts["AWS Access Key ID"], 1)

    def test_verified_live_finding_counts_as_critical_in_summary(self):
        result = ScanResult(target=".")
        result.findings = [
            Finding("f", 1, "x", "SendGrid API Key", "HIGH", "SG.****", verification="verified-live"),
        ]

        self.assertEqual(result.risk_level, "CRITICAL")
        self.assertEqual(result.critical_count, 1)
        self.assertEqual(result.high_count, 0)
        self.assertEqual(result.verified_live_count, 1)


class SarifTests(unittest.TestCase):
    def test_rule_id_is_stable_and_readable(self):
        self.assertEqual(sarif_rule_id("AWS Access Key ID"), "secret-aws-access-key-id")

    def test_sarif_export_uses_2_1_0_schema(self):
        result = ScanResult(target=".")
        result.findings = [
            Finding(
                file="config.py",
                line_number=3,
                line_content='AWS_KEY = "AKIA************MNOP"',
                secret_type="AWS Access Key ID",
                severity="CRITICAL",
                matched_text="AKIA************MNOP",
            )
        ]

        sarif = build_sarif(result)

        self.assertEqual(sarif["version"], "2.1.0")
        self.assertEqual(sarif["runs"][0]["tool"]["driver"]["name"], "FreNiMi Secrets Scanner")
        self.assertEqual(sarif["runs"][0]["results"][0]["ruleId"], "secret-aws-access-key-id")
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")

    def test_sarif_does_not_expose_raw_secret(self):
        raw_secret = "AKIAABCDEFGHIJKLMNOP"
        findings = scan_content(f'AWS_KEY = "{raw_secret}"', "config.py")
        sarif = build_sarif(ScanResult(target=".", findings=findings))

        self.assertNotIn(raw_secret, str(sarif))
        self.assertIn("AKIA************MNOP", str(sarif))

    def test_sarif_does_not_expose_raw_secret_even_with_verify_enabled(self):
        raw_secret = "SG." + ("a" * 22) + "." + ("b" * 43)
        with patch("scanner.verify_secret", return_value="verified-live"):
            findings = scan_content(f'SENDGRID_KEY = "{raw_secret}"', "mail.py", verify=True)
        sarif = build_sarif(ScanResult(target=".", findings=findings))

        self.assertNotIn(raw_secret, str(sarif))
        self.assertEqual(sarif["runs"][0]["results"][0]["properties"]["verificationStatus"], "verified-live")
        self.assertEqual(sarif["runs"][0]["results"][0]["level"], "error")


class JsonExportTests(unittest.TestCase):
    def test_json_export_includes_summary_and_redacted_values(self):
        raw_secret = "AKIAABCDEFGHIJKLMNOP"
        findings = scan_content(f'AWS_KEY = "{raw_secret}"', "config.py")
        result = ScanResult(target=".", files_scanned=1, findings=findings)

        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as f:
            path = f.name
        try:
            export_json(result, path)
            data = json.loads(Path(path).read_text())
        finally:
            Path(path).unlink()

        self.assertEqual(data["summary"]["risk_level"], "CRITICAL")
        self.assertEqual(data["summary"]["severity_counts"]["CRITICAL"], 1)
        self.assertNotIn(raw_secret, json.dumps(data))


if __name__ == "__main__":
    unittest.main()
