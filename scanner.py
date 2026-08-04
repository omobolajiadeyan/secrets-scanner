#!/usr/bin/env python3
"""
Secrets Scanner - Detect exposed API keys, passwords, and credentials in source code.
Author: Omobolaji Adeyan
"""

import re
import os
import sys
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from patterns import SECRET_PATTERNS, SCAN_EXTENSIONS, SKIP_DIRS, SKIP_FILES
from verify import NOT_CHECKED, VERIFIED_LIVE, verify_secret

# ANSI colour codes
RED     = "\033[91m"
YELLOW  = "\033[93m"
GREEN   = "\033[92m"
CYAN    = "\033[96m"
BOLD    = "\033[1m"
RESET   = "\033[0m"

SEVERITY_COLOR = {
    "CRITICAL": RED,
    "HIGH": YELLOW,
    "MEDIUM": CYAN,
    "LOW": GREEN,
}

VERIFICATION_LABEL = {
    "verified-live": "VERIFIED LIVE — ROTATE NOW",
    "verified-invalid": "verified inactive",
    "verification-error": "verification inconclusive",
    "unverified": "verification not supported for this type",
}

VERIFICATION_COLOR = {
    "verified-live": RED,
    "verified-invalid": GREEN,
    "verification-error": YELLOW,
    "unverified": RESET,
}


@dataclass
class Finding:
    file: str
    line_number: int
    line_content: str
    secret_type: str
    severity: str
    matched_text: str
    verification: str = NOT_CHECKED

    @property
    def effective_severity(self) -> str:
        """Severity after accounting for live verification.

        A confirmed-active credential is always CRITICAL, regardless of the
        pattern's baseline severity.
        """
        if self.verification == VERIFIED_LIVE:
            return "CRITICAL"
        return self.severity


@dataclass
class ScanResult:
    target: str
    files_scanned: int = 0
    files_skipped: int = 0
    findings: list = field(default_factory=list)

    @property
    def total_findings(self):
        return len(self.findings)

    @property
    def critical_count(self):
        return sum(1 for f in self.findings if f.effective_severity == "CRITICAL")

    @property
    def high_count(self):
        return sum(1 for f in self.findings if f.effective_severity == "HIGH")

    @property
    def verified_live_count(self):
        return sum(1 for f in self.findings if f.verification == VERIFIED_LIVE)

    @property
    def severity_counts(self):
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in self.findings:
            counts[finding.effective_severity] = counts.get(finding.effective_severity, 0) + 1
        return counts

    @property
    def secret_type_counts(self):
        counts = {}
        for finding in self.findings:
            counts[finding.secret_type] = counts.get(finding.secret_type, 0) + 1
        return dict(sorted(counts.items(), key=lambda item: (-item[1], item[0])))

    @property
    def risk_level(self):
        if self.critical_count:
            return "CRITICAL"
        if self.high_count:
            return "HIGH"
        if self.total_findings:
            return "MEDIUM"
        return "LOW"


def redact(text: str, match: str) -> str:
    """Partially redact a matched secret for safe display."""
    if len(match) <= 8:
        return "*" * len(match)
    return match[:4] + "*" * (len(match) - 8) + match[-4:]


def scan_content(content: str, filepath: str, verify: bool = False) -> list[Finding]:
    findings = []
    lines = content.splitlines()

    for pattern_info in SECRET_PATTERNS:
        regex = re.compile(pattern_info["regex"])
        for line_num, line in enumerate(lines, start=1):
            match = regex.search(line)
            if match:
                matched_text = match.group(0)
                # Verify (if requested) using the raw match while it is
                # still in scope, then immediately redact. The raw value is
                # never stored on the Finding or written anywhere.
                verification = verify_secret(pattern_info["name"], matched_text) if verify else NOT_CHECKED
                redacted_line = line.replace(matched_text, redact(line, matched_text))
                findings.append(Finding(
                    file=filepath,
                    line_number=line_num,
                    line_content=redacted_line.strip(),
                    secret_type=pattern_info["name"],
                    severity=pattern_info["severity"],
                    matched_text=redact(matched_text, matched_text),
                    verification=verification,
                ))

    return findings


def should_scan_file(path: Path) -> bool:
    if path.name in SKIP_FILES:
        return False
    if path.suffix not in SCAN_EXTENSIONS and path.name != ".env":
        return False
    return True


def scan_path(target: str, verify: bool = False) -> ScanResult:
    result = ScanResult(target=target)
    target_path = Path(target)

    if target_path.is_file():
        try:
            content = target_path.read_text(encoding="utf-8", errors="ignore")
            result.files_scanned += 1
            result.findings.extend(scan_content(content, str(target_path), verify=verify))
        except Exception:
            result.files_skipped += 1
        return result

    for root, dirs, files in os.walk(target_path):
        # Prune skip dirs in-place so os.walk doesn't descend into them
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS]

        for filename in files:
            filepath = Path(root) / filename
            if not should_scan_file(filepath):
                result.files_skipped += 1
                continue
            try:
                content = filepath.read_text(encoding="utf-8", errors="ignore")
                result.files_scanned += 1
                result.findings.extend(scan_content(content, str(filepath), verify=verify))
            except Exception:
                result.files_skipped += 1

    return result


def print_results(result: ScanResult, verbose: bool = False):
    print(f"\n{BOLD}{'='*60}{RESET}")
    print(f"{BOLD}  SECRETS SCANNER REPORT{RESET}")
    print(f"{BOLD}{'='*60}{RESET}")
    print(f"  Target    : {result.target}")
    print(f"  Scanned   : {result.files_scanned} files")
    print(f"  Skipped   : {result.files_skipped} files")
    print(f"  Findings  : {result.total_findings} total")
    print(f"{'='*60}")

    if not result.findings:
        print(f"\n{GREEN}No secrets found. Clean!{RESET}\n")
        return

    for finding in result.findings:
        color = SEVERITY_COLOR.get(finding.effective_severity, RESET)
        print(f"\n{color}{BOLD}[{finding.effective_severity}]{RESET} {finding.secret_type}")
        print(f"  File   : {finding.file}:{finding.line_number}")
        if verbose:
            print(f"  Line   : {finding.line_content}")
        print(f"  Match  : {finding.matched_text}")
        if finding.verification != NOT_CHECKED:
            vcolor = VERIFICATION_COLOR.get(finding.verification, RESET)
            label = VERIFICATION_LABEL.get(finding.verification, finding.verification)
            print(f"  Verify : {vcolor}{label}{RESET}")

    print(f"\n{BOLD}Summary:{RESET}")
    print(f"  {RED}CRITICAL : {result.critical_count}{RESET}")
    print(f"  {YELLOW}HIGH     : {result.high_count}{RESET}")
    if result.verified_live_count:
        print(f"  {RED}{BOLD}VERIFIED LIVE : {result.verified_live_count} — rotate these immediately{RESET}")
    print()


def export_json(result: ScanResult, output_file: str):
    findings = []
    for f in result.findings:
        entry = asdict(f)
        entry["effective_severity"] = f.effective_severity
        findings.append(entry)

    data = {
        "summary": {
            "risk_level": result.risk_level,
            "severity_counts": result.severity_counts,
            "secret_type_counts": result.secret_type_counts,
            "verified_live_count": result.verified_live_count,
            "redaction": "matched values are redacted before export",
        },
        "target": result.target,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "total_findings": result.total_findings,
        "findings": findings,
    }
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"{GREEN}Results exported to {output_file}{RESET}")


def sarif_level(severity: str) -> str:
    return {
        "CRITICAL": "error",
        "HIGH": "error",
        "MEDIUM": "warning",
        "LOW": "note",
    }.get(severity, "warning")


def sarif_rule_id(secret_type: str) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", secret_type.lower()).strip("-")
    return f"secret-{normalized}"


def build_sarif(result: ScanResult) -> dict:
    rules_by_id = {}
    sarif_results = []

    for finding in result.findings:
        rule_id = sarif_rule_id(finding.secret_type)
        rules_by_id.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": finding.secret_type,
                "shortDescription": {"text": f"Potential {finding.secret_type} exposure"},
                "fullDescription": {
                    "text": (
                        "A potential secret or credential was detected. "
                        "Review the finding, rotate any exposed credential, "
                        "and move secret material into an approved secret store."
                    )
                },
                "defaultConfiguration": {"level": sarif_level(finding.effective_severity)},
                "properties": {"security-severity": finding.effective_severity},
            },
        )
        message = f"{finding.secret_type} detected in source code. The matched value is redacted in this report."
        if finding.verification == "verified-live":
            message += " This credential was confirmed ACTIVE by a live check against its provider — rotate it immediately."
        elif finding.verification == "verified-invalid":
            message += " A live check confirmed this credential is no longer active."

        sarif_results.append(
            {
                "ruleId": rule_id,
                "level": sarif_level(finding.effective_severity),
                "message": {"text": message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": finding.file.replace("\\", "/")},
                            "region": {
                                "startLine": finding.line_number,
                                "snippet": {"text": finding.line_content},
                            },
                        }
                    }
                ],
                "properties": {
                    "severity": finding.effective_severity,
                    "redactedMatch": finding.matched_text,
                    "verificationStatus": finding.verification,
                },
            }
        )

    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "FreNiMi Secrets Scanner",
                        "informationUri": "https://github.com/omobolajiadeyan/secrets-scanner",
                        "rules": list(rules_by_id.values()),
                    }
                },
                "results": sarif_results,
            }
        ],
    }


def export_sarif(result: ScanResult, output_file: str):
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(build_sarif(result), f, indent=2)
    print(f"{GREEN}SARIF results exported to {output_file}{RESET}")


def export_results(result: ScanResult, output_file: str, output_format: str):
    if output_format == "sarif":
        export_sarif(result, output_file)
    else:
        export_json(result, output_file)


def main():
    parser = argparse.ArgumentParser(
        description="Secrets Scanner - Find exposed credentials in source code",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python scanner.py .                          # Scan current directory
  python scanner.py /path/to/project           # Scan a specific path
  python scanner.py myfile.py --verbose        # Show full line content
  python scanner.py . --output results.json    # Export findings to JSON
  python scanner.py . --format sarif -o results.sarif
  python scanner.py . --severity CRITICAL      # Only show critical findings
  python scanner.py . --verify                 # Also check if secrets are still active
        """,
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show full line content")
    parser.add_argument("--output", "-o", help="Export results to a file")
    parser.add_argument(
        "--verify",
        action="store_true",
        help=(
            "Make a live API call to each secret's own provider (GitHub, Slack, Stripe, "
            "SendGrid, Discord) to check whether it is still active. Sends the detected "
            "credential over the network to that provider's verification endpoint only; "
            "the raw value is never logged, printed, or written to any output file."
        ),
    )
    parser.add_argument(
        "--format",
        choices=["json", "sarif"],
        default="json",
        help="Output format used with --output",
    )
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Filter results by minimum severity",
    )

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"{RED}Error: Path '{args.target}' does not exist.{RESET}")
        sys.exit(1)

    if args.verify:
        print(f"{CYAN}Scanning: {args.target} (with live verification) ...{RESET}")
    else:
        print(f"{CYAN}Scanning: {args.target} ...{RESET}")
    result = scan_path(args.target, verify=args.verify)

    # Apply severity filter
    if args.severity:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        min_idx = order.index(args.severity)
        result.findings = [f for f in result.findings if order.index(f.severity) <= min_idx]

    print_results(result, verbose=args.verbose)

    if args.output:
        export_results(result, args.output, args.format)

    # Exit with non-zero code if critical findings exist (useful for CI/CD)
    if result.critical_count > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
