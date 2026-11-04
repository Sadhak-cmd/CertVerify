"""
revoke_certificate.py
Applies a SHA-256 hash-chain pattern to revoke certificates in a tamper-evident revocations table.

Hash formula:
    SHA-256( cert_id | reason | prev_hash )

Genesis block concept (matches issue_certificate.py):
    The very first entry in the revocation ledger uses GENESIS_HASH ("0" * 64)
    as its "prev_hash". Every subsequent entry's prev_hash equals the revocation_hash
    of the block that came immediately before it, forming an unbroken chain.
"""

import hashlib
from typing import Optional, Any
from db_connect import get_connection

# Sentinel used when there are no prior blocks in the chain (the genesis case).
GENESIS_HASH = "0" * 64


def get_last_revocation_hash(cursor) -> str:
    """
    Return the revocation_hash of the most recently inserted revocation record,
    or GENESIS_HASH if no revocations exist yet.
    """
    cursor.execute(
        "SELECT revocation_hash FROM revocations ORDER BY revocation_id DESC LIMIT 1;"
    )
    result = cursor.fetchone()
    if not result:
        return GENESIS_HASH
    return result[0] if isinstance(result, tuple) else result["revocation_hash"]


def build_revocation_hash_input(cert_id: int, reason: str, prev_hash: str) -> str:
    """
    Produce a deterministic, canonical string for the revocation entry.
    """
    return f"{cert_id}|{reason}|{prev_hash}"


def compute_revocation_hash(cert_id: int, reason: str, prev_hash: str) -> str:
    """Return the SHA-256 hex digest of the canonical revocation string."""
    data = build_revocation_hash_input(cert_id, reason, prev_hash)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def revoke_certificate(cert_id: int, reason: str) -> str:
    """
    Look up the most recent revocation_hash in the revocations table (or GENESIS_HASH),
    compute a new hash from cert_id + reason + prev_hash, insert the new revocation record,
    and return the new revocation hash.

    Parameters
    ----------
    cert_id : int
        The certificate ID to revoke.
    reason : str
        The human-readable reason for revocation (e.g. 'Issued in error', 'Academic misconduct').

    Returns
    -------
    str
        The new SHA-256 revocation_hash appended to the revocation chain.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        prev_hash = get_last_revocation_hash(cursor)
        new_hash = compute_revocation_hash(cert_id, reason, prev_hash)

        cursor.execute(
            """
            INSERT INTO revocations (cert_id, reason, revocation_hash, prev_hash)
            VALUES (%s, %s, %s, %s);
            """,
            (cert_id, reason, new_hash, prev_hash),
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    print(f"Certificate {cert_id} revoked. Reason: {reason} (hash: {new_hash[:16]}...)")
    return new_hash


class RevocationRecord(tuple):
    """
    Lightweight record representing a revocation entry.
    Supports:
      - Tuple unpacking: reason, revoked_at = record
      - Attribute access: record.reason, record.revoked_at
      - Dict-like indexing: record['reason'], record['revoked_at']
    """
    def __new__(cls, reason: str, revoked_at: Any):
        return super().__new__(cls, (reason, revoked_at))

    def __init__(self, reason: str, revoked_at: Any):
        self.reason = reason
        self.revoked_at = revoked_at

    def __getitem__(self, item):
        if item == "reason":
            return self.reason
        if item == "revoked_at":
            return self.revoked_at
        return super().__getitem__(item)

    def get(self, key: str, default: Any = None) -> Any:
        if key == "reason":
            return self.reason
        if key == "revoked_at":
            return self.revoked_at
        return default


def is_revoked(cert_id: int) -> Optional[RevocationRecord]:
    """
    Return the most recent revocation record for a cert_id if one exists,
    or None otherwise. Fast, indexed lookup designed to run during verification.

    Parameters
    ----------
    cert_id : int
        The certificate ID to check.

    Returns
    -------
    RevocationRecord or None
        RevocationRecord with (reason, revoked_at) if revoked, else None.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT reason, revoked_at
            FROM revocations
            WHERE cert_id = %s
            ORDER BY revocation_id DESC
            LIMIT 1;
            """,
            (cert_id,),
        )
        row = cursor.fetchone()
        if not row:
            return None
        return RevocationRecord(reason=row[0], revoked_at=row[1])
    finally:
        cursor.close()
        conn.close()


if __name__ == "__main__":
    import sys
    test_cert_id = int(sys.argv[1]) if len(sys.argv) > 1 else 1
    test_reason = sys.argv[2] if len(sys.argv) > 2 else "Issued in error"
    revoke_certificate(cert_id=test_cert_id, reason=test_reason)

