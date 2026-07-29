# Project Evidence

This page records reproducible evidence for Secrets Scanner. The checked-in
sample contains fake credential-shaped strings only; it must not contain real
secrets.

## Technical Evidence

Snapshot verified on July 29, 2026:

- Secret patterns: AWS, GitHub, Slack, Stripe, private keys, database URLs,
  JWTs, generic API keys, and related credential forms.
- Output safety: matched values are redacted before terminal, JSON, and SARIF
  output.
- Automation output: JSON and SARIF 2.1.0.
- CI behavior: critical findings return exit code `2`.
- GitHub Action: reusable composite action for CI and Code Scanning.
- Browser review path: `web/` report viewer for exported JSON.
- Runtime dependency posture: Python standard library only.

## Reproducible Demo

```bash
python scanner.py sample/ --verbose
python scanner.py sample/ --output web/sample-report.json
python scanner.py sample/ --format sarif --output secrets-scanner.sarif
```

Expected sample summary:

| Metric | Value |
| --- | ---: |
| Files scanned | 1 |
| Total findings | 2 |
| Critical findings | 1 |
| High findings | 1 |

## Evidence Boundaries

This is deterministic pattern scanning, not a complete secret-management
program. It should be paired with credential rotation, least privilege,
provider-native secret scanning, and repository controls.
