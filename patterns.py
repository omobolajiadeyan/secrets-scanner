"""
Regex patterns for detecting exposed secrets, API keys, and credentials.
"""

SECRET_PATTERNS = [
    {
        "name": "AWS Access Key ID",
        "regex": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
    },
    {
        "name": "AWS Secret Access Key",
        "regex": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "severity": "CRITICAL",
    },
    {
        "name": "Generic API Key",
        "regex": r"(?i)(api[_\-\s]?key|apikey)\s*[:=]\s*['\"]?[a-zA-Z0-9\-_]{16,64}['\"]?",
        "severity": "HIGH",
    },
    {
        "name": "Generic Secret",
        "regex": r"(?i)(secret|password|passwd|pwd)\s*[:=]\s*['\"]?[a-zA-Z0-9@#$%^&*\-_!]{8,64}['\"]?",
        "severity": "HIGH",
    },
    {
        "name": "GitHub Token",
        "regex": r"gh[pousr]_[A-Za-z0-9_]{36,255}",
        "severity": "CRITICAL",
    },
    {
        "name": "Slack Token",
        "regex": r"xox[baprs]-[0-9a-zA-Z\-]{10,72}",
        "severity": "CRITICAL",
    },
    {
        "name": "Stripe Secret Key",
        "regex": r"sk_(live|test)_[0-9a-zA-Z]{24,}",
        "severity": "CRITICAL",
    },
    {
        "name": "Google API Key",
        "regex": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "HIGH",
    },
    {
        "name": "Private Key Block",
        "regex": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
        "severity": "CRITICAL",
    },
    {
        "name": "JWT Token",
        "regex": r"eyJ[a-zA-Z0-9]{10,}\.[a-zA-Z0-9\-_]{10,}\.[a-zA-Z0-9\-_]{10,}",
        "severity": "MEDIUM",
    },
    {
        "name": "Database Connection String",
        "regex": r"(?i)(mongodb|postgres|mysql|redis|sqlite):\/\/[^\s'\"]{8,}",
        "severity": "CRITICAL",
    },
    {
        "name": "Basic Auth in URL",
        "regex": r"https?:\/\/[a-zA-Z0-9_\-\.]+:[a-zA-Z0-9_\-\.@!#$%^&*]+@",
        "severity": "HIGH",
    },
    {
        "name": "SendGrid API Key",
        "regex": r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}",
        "severity": "HIGH",
    },
    {
        "name": "Twilio Account SID",
        "regex": r"AC[a-f0-9]{32}",
        "severity": "HIGH",
    },
    {
        "name": "Discord Bot Token",
        "regex": r"[MN][a-zA-Z0-9]{23}\.[a-zA-Z0-9\-_]{6}\.[a-zA-Z0-9\-_]{27}",
        "severity": "HIGH",
    },
]

# File extensions to scan
SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".env", ".yaml", ".yml",
    ".json", ".toml", ".ini", ".cfg", ".conf", ".sh", ".bash",
    ".php", ".rb", ".go", ".java", ".cs", ".cpp", ".c", ".h",
    ".xml", ".properties", ".gradle", ".tf", ".tfvars",
}

# Paths to always skip
SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    "dist", "build", ".idea", ".vscode", "vendor",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "poetry.lock", "Pipfile.lock",
}
