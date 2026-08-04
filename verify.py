"""
Optional live credential verification.

Only used when --verify is passed. Each check makes a single short-timeout
HTTP request to the credential's OWN provider API (never a third party) to
test whether it is still active. This module never logs, prints, or writes
the raw secret anywhere — callers pass it in, get a status string back, and
must discard the raw value immediately. Uses the standard library only, to
keep the project's zero-dependency guarantee.
"""

import json
import urllib.error
import urllib.request

TIMEOUT_SECONDS = 5

VERIFIED_LIVE = "verified-live"
VERIFIED_INVALID = "verified-invalid"
VERIFICATION_ERROR = "verification-error"
NOT_CHECKED = "not-checked"
UNSUPPORTED = "unverified"


def _get(url: str, headers: dict) -> int:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
        return resp.status


def _post_form(url: str, data: bytes, headers: dict) -> dict:
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=TIMEOUT_SECONDS) as resp:
        return json.loads(resp.read().decode("utf-8"))


def verify_github_token(token: str) -> str:
    try:
        status = _get(
            "https://api.github.com/user",
            headers={"Authorization": f"Bearer {token}", "User-Agent": "secrets-scanner"},
        )
        return VERIFIED_LIVE if status == 200 else VERIFICATION_ERROR
    except urllib.error.HTTPError as exc:
        return VERIFIED_INVALID if exc.code in (401, 403) else VERIFICATION_ERROR
    except Exception:
        return VERIFICATION_ERROR


def verify_slack_token(token: str) -> str:
    try:
        body = _post_form(
            "https://slack.com/api/auth.test",
            data=f"token={token}".encode("utf-8"),
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        return VERIFIED_LIVE if body.get("ok") else VERIFIED_INVALID
    except Exception:
        return VERIFICATION_ERROR


def verify_stripe_key(key: str) -> str:
    try:
        status = _get("https://api.stripe.com/v1/balance", headers={"Authorization": f"Bearer {key}"})
        return VERIFIED_LIVE if status == 200 else VERIFICATION_ERROR
    except urllib.error.HTTPError as exc:
        return VERIFIED_INVALID if exc.code == 401 else VERIFICATION_ERROR
    except Exception:
        return VERIFICATION_ERROR


def verify_sendgrid_key(key: str) -> str:
    try:
        status = _get("https://api.sendgrid.com/v3/user/account", headers={"Authorization": f"Bearer {key}"})
        return VERIFIED_LIVE if status == 200 else VERIFICATION_ERROR
    except urllib.error.HTTPError as exc:
        return VERIFIED_INVALID if exc.code == 401 else VERIFICATION_ERROR
    except Exception:
        return VERIFICATION_ERROR


def verify_discord_token(token: str) -> str:
    try:
        status = _get("https://discord.com/api/v10/users/@me", headers={"Authorization": f"Bot {token}"})
        return VERIFIED_LIVE if status == 200 else VERIFICATION_ERROR
    except urllib.error.HTTPError as exc:
        return VERIFIED_INVALID if exc.code == 401 else VERIFICATION_ERROR
    except Exception:
        return VERIFICATION_ERROR


# Secret type name -> verifier. Only types with a safe, well-documented
# "check if this credential is still active" endpoint are included. Types
# like AWS Access Key ID (needs a paired secret key) or Twilio Account SID
# (needs a paired auth token) are intentionally left unsupported for now
# rather than guessed at.
VERIFIERS = {
    "GitHub Token": verify_github_token,
    "Slack Token": verify_slack_token,
    "Stripe Secret Key": verify_stripe_key,
    "SendGrid API Key": verify_sendgrid_key,
    "Discord Bot Token": verify_discord_token,
}


def verify_secret(secret_type: str, raw_value: str) -> str:
    """Return a verification status for a raw (unredacted) secret value.

    Callers must call this with the in-memory raw match immediately after
    detection and discard the raw value as soon as this returns — the
    result is a status string, never the secret itself.
    """
    verifier = VERIFIERS.get(secret_type)
    if verifier is None:
        return UNSUPPORTED
    return verifier(raw_value)
