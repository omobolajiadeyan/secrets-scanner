import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from scanner import Finding, ScanResult, redact, scan_content, scan_path, should_scan_file


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


if __name__ == "__main__":
    unittest.main()
