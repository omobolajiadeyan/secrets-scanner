#!/usr/bin/env python3
"""
Secrets Scanner - Detect exposed API keys, passwords, and credentials in source code.
Author: Omobolaji Adeyanju
"""

import re
import os
import sys
import json
import argparse
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional
from patterns import SECRET_PATTERNS, SCAN_EXTENSIONS, SKIP_DIRS, SKIP_FILES

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


@dataclass
class Finding:
    file: str
    line_number: int
    line_content: str
    secret_type: str
    severity: str
    matched_text: str


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
        return sum(1 for f in self.findings if f.severity == "CRITICAL")

    @property
    def high_count(self):
        return sum(1 for f in self.findings if f.severity == "HIGH")


def redact(text: str, match: str) -> str:
    """Partially redact a matched secret for safe display."""
    if len(match) <= 8:
        return "*" * len(match)
    return match[:4] + "*" * (len(match) - 8) + match[-4:]


def scan_content(content: str, filepath: str) -> list[Finding]:
    findings = []
    lines = content.splitlines()

    for pattern_info in SECRET_PATTERNS:
        regex = re.compile(pattern_info["regex"])
        for line_num, line in enumerate(lines, start=1):
            match = regex.search(line)
            if match:
                matched_text = match.group(0)
                redacted_line = line.replace(matched_text, redact(line, matched_text))
                findings.append(Finding(
                    file=filepath,
                    line_number=line_num,
                    line_content=redacted_line.strip(),
                    secret_type=pattern_info["name"],
                    severity=pattern_info["severity"],
                    matched_text=redact(matched_text, matched_text),
                ))

    return findings


def should_scan_file(path: Path) -> bool:
    if path.name in SKIP_FILES:
        return False
    if path.suffix not in SCAN_EXTENSIONS and path.name != ".env":
        return False
    return True


def scan_path(target: str) -> ScanResult:
    result = ScanResult(target=target)
    target_path = Path(target)

    if target_path.is_file():
        try:
            content = target_path.read_text(encoding="utf-8", errors="ignore")
            result.files_scanned += 1
            result.findings.extend(scan_content(content, str(target_path)))
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
                result.findings.extend(scan_content(content, str(filepath)))
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
        color = SEVERITY_COLOR.get(finding.severity, RESET)
        print(f"\n{color}{BOLD}[{finding.severity}]{RESET} {finding.secret_type}")
        print(f"  File   : {finding.file}:{finding.line_number}")
        if verbose:
            print(f"  Line   : {finding.line_content}")
        print(f"  Match  : {finding.matched_text}")

    print(f"\n{BOLD}Summary:{RESET}")
    print(f"  {RED}CRITICAL : {result.critical_count}{RESET}")
    print(f"  {YELLOW}HIGH     : {result.high_count}{RESET}")
    print()


def export_json(result: ScanResult, output_file: str):
    data = {
        "target": result.target,
        "files_scanned": result.files_scanned,
        "files_skipped": result.files_skipped,
        "total_findings": result.total_findings,
        "findings": [asdict(f) for f in result.findings],
    }
    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)
    print(f"{GREEN}Results exported to {output_file}{RESET}")


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
  python scanner.py . --severity CRITICAL      # Only show critical findings
        """,
    )
    parser.add_argument("target", help="File or directory to scan")
    parser.add_argument("--verbose", "-v", action="store_true", help="Show full line content")
    parser.add_argument("--output", "-o", help="Export results to JSON file")
    parser.add_argument(
        "--severity",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW"],
        help="Filter results by minimum severity",
    )

    args = parser.parse_args()

    if not os.path.exists(args.target):
        print(f"{RED}Error: Path '{args.target}' does not exist.{RESET}")
        sys.exit(1)

    print(f"{CYAN}Scanning: {args.target} ...{RESET}")
    result = scan_path(args.target)

    # Apply severity filter
    if args.severity:
        order = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
        min_idx = order.index(args.severity)
        result.findings = [f for f in result.findings if order.index(f.severity) <= min_idx]

    print_results(result, verbose=args.verbose)

    if args.output:
        export_json(result, args.output)

    # Exit with non-zero code if critical findings exist (useful for CI/CD)
    if result.critical_count > 0:
        sys.exit(2)


if __name__ == "__main__":
    main()
