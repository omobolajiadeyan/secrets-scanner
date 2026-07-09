# Secrets Scanner

A lightweight command-line tool that detects exposed API keys, passwords, tokens, and credentials in source code — before they end up in production or a public repository.

## Why This Matters

Exposed secrets in source code are one of the most common causes of data breaches. This tool helps developers catch credentials before they are committed or deployed.

## Features

- Detects 15+ secret types including AWS keys, GitHub tokens, Stripe keys, database URLs, JWT tokens, and more
- Scans entire directories recursively, respecting `.gitignore`-style skip rules
- Color-coded severity levels: `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`
- Redacts matched values in output to prevent further exposure
- JSON export for integration into CI/CD pipelines
- Zero third-party dependencies — pure Python standard library
- Returns exit code `2` when critical findings are found (CI/CD friendly)

## Supported Secret Types

| Secret Type | Severity |
|---|---|
| AWS Access Key ID | CRITICAL |
| AWS Secret Access Key | CRITICAL |
| GitHub Token | CRITICAL |
| Slack Token | CRITICAL |
| Stripe Secret Key | CRITICAL |
| Private Key (RSA/EC/SSH) | CRITICAL |
| Database Connection String | CRITICAL |
| Generic API Key | HIGH |
| Generic Password/Secret | HIGH |
| Google API Key | HIGH |
| SendGrid API Key | HIGH |
| Discord Bot Token | HIGH |
| Basic Auth in URL | HIGH |
| Twilio Account SID | HIGH |
| JWT Token | MEDIUM |

## Installation

```bash
git clone https://github.com/omobolajiadeyan/secrets-scanner.git
cd secrets-scanner
python --version  # Requires Python 3.10+
```

No pip install needed — uses only the Python standard library.

## Usage

```bash
# Scan current directory
python scanner.py .

# Scan a specific path
python scanner.py /path/to/project

# Show full line content for each finding
python scanner.py . --verbose

# Only show CRITICAL findings
python scanner.py . --severity CRITICAL

# Export results to JSON (for CI/CD or reporting)
python scanner.py . --output results.json

# Scan a single file
python scanner.py config.py --verbose
```

## Example Output

```
Scanning: . ...

============================================================
  SECRETS SCANNER REPORT
============================================================
  Target    : .
  Scanned   : 12 files
  Skipped   : 3 files
  Findings  : 3 total
============================================================

[CRITICAL] AWS Access Key ID
  File   : sample/example_bad.py:6
  Match  : AKIA****XAMPLE

[CRITICAL] Database Connection String
  File   : sample/example_bad.py:10
  Match  : postg****5432/mydb

[HIGH] Generic Secret
  File   : sample/example_bad.py:18
  Match  : MySup****d123

Summary:
  CRITICAL : 2
  HIGH     : 1
```

## CI/CD Integration

```yaml
# .github/workflows/secrets-check.yml
- name: Scan for secrets
  run: python scanner.py . --severity HIGH
  # Exits with code 2 if CRITICAL findings are found
```

## Project Structure

```
secrets-scanner/
├── scanner.py       # Main CLI entrypoint
├── patterns.py      # Regex patterns for each secret type
├── requirements.txt # No dependencies needed
├── sample/
│   └── example_bad.py   # Intentionally insecure file for testing
└── README.md
```

## Author

**Omobolaji Adeyan** — Cybersecurity Portfolio Project  
[GitHub](https://github.com/omobolajiadeyan) · [Website](https://omobolajiadeyan.com)
