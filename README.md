# Secrets Scanner

[![Tests](https://github.com/omobolajiadeyan/secrets-scanner/actions/workflows/tests.yml/badge.svg)](https://github.com/omobolajiadeyan/secrets-scanner/actions/workflows/tests.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)
[![Maintainer](https://img.shields.io/badge/Maintainer-Omobolaji_Adeyan-0A66C2?style=flat-square)](https://github.com/omobolajiadeyan)

A lightweight Python security tool that detects exposed API keys, passwords,
tokens, private keys, and connection strings before they reach production or a
public repository.

Built and maintained by [Omobolaji Adeyan](https://github.com/omobolajiadeyan)
as part of a practical security-engineering toolkit.

## Why This Matters

Exposed secrets are a common source of security incidents. This scanner helps
developers catch obvious credential leaks locally, in pull requests, and in
GitHub Code Scanning workflows.

Pattern-based scanners are noisy: most findings are old, rotated, or
placeholder-shaped strings, not live credentials. The optional `--verify`
flag closes that gap by checking whether a detected secret is actually still
active, so triage effort goes to what matters first.

## Features

- Detects AWS keys, GitHub tokens, Stripe keys, private keys, database URLs,
  JWTs, generic passwords, and more
- Optional `--verify` flag confirms whether GitHub, Slack, Stripe, SendGrid,
  and Discord credentials are still live before you triage them
- Redacts matched values in terminal, JSON, and SARIF output — even with
  `--verify` enabled, the raw secret is never logged or written anywhere
- Exports JSON for automation and SARIF 2.1.0 for GitHub Code Scanning
- Ships as a reusable GitHub Action
- Includes a browser report viewer for redacted JSON evidence
- Uses only the Python standard library
- Returns exit code `2` when critical findings are found

## Project Evidence

The sample evidence run scans a public-safe fixture containing fake
credential-shaped strings, redacts matched values, and produces reviewable JSON
and SARIF output.

![Secrets Scanner evidence](docs/assets/secrets-scanner-evidence.svg)

See [Project Evidence](docs/PROJECT_EVIDENCE.md) for exact commands, expected
sample counts, redaction boundaries, and output safety notes. External
reviewers can use the [Evaluator Guide](docs/EVALUATOR_GUIDE.md) for a
five-minute review.

## Supported Secret Types

| Secret Type | Severity | Live Verification |
|---|---|---|
| AWS Access Key ID | CRITICAL | — |
| AWS Secret Access Key | CRITICAL | — |
| GitHub Token | CRITICAL | ✅ |
| Slack Token | CRITICAL | ✅ |
| Stripe Secret Key | CRITICAL | ✅ |
| Private Key Block | CRITICAL | — |
| Database Connection String | CRITICAL | — |
| Generic API Key | HIGH | — |
| Generic Secret | HIGH | — |
| Google API Key | HIGH | — |
| SendGrid API Key | HIGH | ✅ |
| Discord Bot Token | HIGH | ✅ |
| Basic Auth in URL | HIGH | — |
| Twilio Account SID | HIGH | — |
| JWT Token | MEDIUM | — |

AWS and Twilio aren't verifiable from a single matched string — both need a
paired secret (access key + secret key, or account SID + auth token) that the
scanner has no reliable way to correlate across a file. Rather than guess,
verification is left unsupported for those types.

## Live Credential Verification (`--verify`, opt-in)

```bash
python scanner.py . --verify
```

When a detected secret's type supports it, the scanner makes a single,
short-timeout (5s) API call **directly to that credential's own provider**
(never a third party) to check whether it's still active:

- **GitHub Token** → `GET api.github.com/user`
- **Slack Token** → `POST slack.com/api/auth.test`
- **Stripe Secret Key** → `GET api.stripe.com/v1/balance`
- **SendGrid API Key** → `GET api.sendgrid.com/v3/user/account`
- **Discord Bot Token** → `GET discord.com/api/v10/users/@me`

Each finding is labeled `verified-live`, `verified-invalid`,
`verification-error` (network/timeout — treated as inconclusive, not a
verdict), or `unverified` (type not supported). A `verified-live` finding is
always reported as CRITICAL regardless of its base severity, in both the
terminal summary and SARIF output.

**This is opt-in and off by default.** Running it means detected credentials
are sent over the network to their provider's own verification endpoint —
still never logged, printed, or written to any output file, but it is real
network activity worth knowing about before enabling it in a shared CI
pipeline. In `--verify` mode, the raw match is held in memory only for the
duration of that one request, then discarded; only the redacted value and the
verification status are ever recorded.

## Installation

```bash
git clone https://github.com/omobolajiadeyan/secrets-scanner.git
cd secrets-scanner
python --version
```

Python 3.10+ is recommended. No third-party packages are required.

## Local Usage

```bash
# Scan the current directory
python scanner.py .

# Scan a specific file or directory
python scanner.py /path/to/project

# Show redacted line context
python scanner.py . --verbose

# Only report HIGH and CRITICAL findings
python scanner.py . --severity HIGH

# Export JSON
python scanner.py . --output results.json

# Export SARIF for GitHub Code Scanning
python scanner.py . --format sarif --output secrets-scanner.sarif

# Also check whether verifiable secret types are still active
python scanner.py . --verify

# Run the bundled public-safe sample
python scanner.py sample/ --verbose
python scanner.py sample/ --output web/sample-report.json
```

## Browser Report Viewer

The `web/` folder provides a lightweight viewer for exported JSON reports. It
loads the checked-in `web/sample-report.json` by default and can load a fresh
export from the scanner.

```bash
python scanner.py sample/ --output web/sample-report.json
cd web
python3 -m http.server 8080
```

Open `http://127.0.0.1:8080/` to review severity counts, secret-type counts,
redacted findings, and file/line evidence.

## GitHub Action Usage

```yaml
name: Secrets Scanner

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read
  security-events: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: omobolajiadeyan/secrets-scanner@main
        with:
          path: .
          severity: HIGH
          output: secrets-scanner.sarif
          verify: "false" # set "true" to check GitHub/Slack/Stripe/SendGrid/Discord secrets are still active
      - uses: github/codeql-action/upload-sarif@v3
        if: always()
        with:
          sarif_file: secrets-scanner.sarif
```

## Output Safety

The scanner redacts matched values before printing or exporting results. SARIF
contains the finding type, severity, file path, line number, and redacted
context, but not the raw secret. This holds true with `--verify` enabled too —
see [Live Credential Verification](#live-credential-verification---verify-opt-in)
for exactly what that flag sends over the network and what it never records.

If you find a real secret in a repository, rotate it immediately. Removing it
from the latest commit is not enough because it may still exist in Git history.

## Project Structure

```text
secrets-scanner/
|-- action.yml
|-- scanner.py
|-- patterns.py
|-- verify.py
|-- docs/
|   |-- EVALUATOR_GUIDE.md
|   `-- PROJECT_EVIDENCE.md
|-- sample/
|   `-- example_bad.py
|-- tests/
|   |-- test_scanner.py
|   `-- test_verify.py
|-- web/
|   |-- index.html
|   |-- app.js
|   |-- style.css
|   `-- sample-report.json
`-- README.md
```

## Limits

This tool uses deterministic patterns and should be treated as a lightweight
guardrail, not a complete secret-management program. It may miss unusual
formats and may flag false positives. Use it alongside secret rotation,
least-privilege credentials, branch protection, code review, and platform-level
secret scanning. Live verification covers 5 of 15 secret types (see the table
above) and treats network errors as inconclusive, not as proof a credential is
safe — an unreachable provider is reported as `verification-error`, never as
verified-inactive.

## Part of the Security Automation Toolkit

Secrets Scanner is one piece of a practical security-automation toolkit. The others:

- **[PhishGuard AI](https://github.com/omobolajiadeyan/phishguard-ai)** — explainable offline phishing detection (flagship, on GitHub Marketplace)
- **[Log Analyzer](https://github.com/omobolajiadeyan/log-analyzer)** — MITRE ATT&CK-mapped log threat detection
- **[BehaviorSense](https://github.com/omobolajiadeyan/behaviorsense)** — UEBA-style behavioral anomaly detection
- **[CVE Dashboard](https://github.com/omobolajiadeyan/cve-dashboard)** — live NVD vulnerability intelligence
- **[VulnGPT](https://github.com/omobolajiadeyan/vulngpt)** — CVE-to-remediation triage assistant

Full portfolio: [github.com/omobolajiadeyan](https://github.com/omobolajiadeyan)

## Author

**Omobolaji Adeyan**  
Security Engineer and open-source security tooling maintainer  
[GitHub](https://github.com/omobolajiadeyan) | [Website](https://omobolajiadeyan.com)
