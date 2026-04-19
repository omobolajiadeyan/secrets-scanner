# WARNING: This file is intentionally insecure for DEMO/TESTING purposes only.
# All values below are FAKE placeholders — never use patterns like these.

import os

# BAD: hardcoded AWS credentials
AWS_ACCESS_KEY_ID = "AKIA_FAKE_KEY_EXAMPLE"
AWS_SECRET_ACCESS_KEY = "FAKE/SECRET/KEY/DO_NOT_USE_bPxRfiCYEXAMPLEKEY"

# BAD: hardcoded database URL
DATABASE_URL = "postgres://admin:FAKE_PASSWORD@db.example.com:5432/mydb"

# BAD: hardcoded API key  (pattern: stripe-like key — value is intentionally fake)
api_key = "sk_live_FAKE_KEY_FOR_DEMO_ONLY_NOT_REAL"

# BAD: hardcoded password in config dict
config = {
    "host": "localhost",
    "password": "FAKE_PASSWORD_EXAMPLE",
    "username": "root",
}

# GOOD: Use environment variables instead
CORRECT_API_KEY = os.environ.get("API_KEY")
CORRECT_DB_URL = os.environ.get("DATABASE_URL")
