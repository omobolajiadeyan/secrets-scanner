# Evaluator Guide

Use this path to evaluate Secrets Scanner quickly.

1. Run the tests:

   ```bash
   python -m unittest discover -s tests -v
   ```

2. Run the sample scan:

   ```bash
   python scanner.py sample/ --verbose
   ```

3. Export JSON and view it:

   ```bash
   python scanner.py sample/ --output web/sample-report.json
   cd web
   python3 -m http.server 8080
   ```

4. Export SARIF:

   ```bash
   python scanner.py sample/ --format sarif --output secrets-scanner.sarif
   ```

Review `patterns.py`, `scanner.py`, `tests/test_scanner.py`, and the `web/`
viewer. Confirm raw sample secret strings do not appear in exported reports.
