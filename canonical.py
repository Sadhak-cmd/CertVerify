"""
canonical.py
Shared helper for deterministic, canonical serialization of certificate data.

Both signing (issue_signed_certificate.py) and verification (verify_credential.py)
MUST use this exact logic so that data string reconstruction is bit-for-bit identical,
preventing false 'invalid' verification failures on legitimate certificates.

Version 1 credentials sign the whole canonical certificate string (canonical_cert_data).
Version 2 credentials sign a list of per-field salted commitments (signing_payload), which
lets a holder reveal only some fields while the signature still verifies.
"""

import hashlib
import json
import secrets
from decimal import Decimal
import datetime
from typing import Any, Dict

# Fields a verifier always needs: cert_id (revocation lookup) and institution_id (whose key).
CORE_FIELDS = ("cert_id", "institution_id")


def canonical_cert_dict(cert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Produce a normalized dictionary of certificate fields with consistent formatting:
    - cert_id, student_id, institution_id: int
    - course_name: str
    - grade: formatted to 2 decimal places (e.g. '8.70') if numeric, or str/None
    - issue_date: formatted as 'YYYY-MM-DD HH:MM:SS' (trimmed to 19 characters)
    """
    normalized = {}
    for key, value in cert.items():
        if key == "grade" and value is not None:
            normalized[key] = f"{float(value):.2f}"
        elif key == "issue_date" and value is not None:
            normalized[key] = str(value)[:19]
        elif isinstance(value, Decimal):
            normalized[key] = f"{float(value):.2f}"
        elif isinstance(value, (datetime.datetime, datetime.date)):
            normalized[key] = str(value)[:19]
        elif isinstance(value, int):
            normalized[key] = int(value)
        elif value is None:
            normalized[key] = None
        else:
            normalized[key] = str(value)
    return normalized


def canonical_cert_data(cert: Dict[str, Any]) -> str:
    """
    Produce a deterministic, sorted-key JSON string from certificate fields.

    Guarantees identical representation whether the input dictionary comes directly
    from a MySQL cursor (with Decimal and datetime objects) or was loaded from a
    JSON credential package file (with strings).
    """
    norm = canonical_cert_dict(cert)
    return json.dumps(norm, sort_keys=True, default=str)


# ----------------------------------------------------------------------------
# Version 2: salted per-field commitments (selective disclosure)
# ----------------------------------------------------------------------------

def make_salt() -> str:
    """128 random bits. The salt stops anyone guessing a hidden grade by hashing 0.00-10.00."""
    return secrets.token_hex(16)


def field_commitment(field: str, value: Any, salt: str) -> str:
    """SHA-256 commitment to one field: hides the value until the holder reveals value + salt."""
    normalized = canonical_cert_dict({field: value})[field]
    blob = json.dumps([salt, field, normalized], separators=(",", ":"), sort_keys=True)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def signing_payload(cert_id: Any, institution_id: Any, commitments: Dict[str, str]) -> str:
    """
    The exact string that is RSA-signed for a v2 credential: the two always-visible fields plus
    every field's commitment, in a fixed order. Hidden fields therefore stay covered by the
    signature without being revealed.
    """
    return json.dumps(
        {
            "v": 2,
            "cert_id": int(cert_id),
            "institution_id": int(institution_id),
            "commitments": {k: commitments[k] for k in sorted(commitments)},
        },
        sort_keys=True,
        separators=(",", ":"),
    )
