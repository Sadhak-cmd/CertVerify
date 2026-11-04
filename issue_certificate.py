"""
issue_certificate.py
Inserts a new certificate and appends a block to the hash chain.

Hash formula (must match verify_certificate.py exactly):
    SHA-256( student_id | institution_id | course_name | grade | issue_date | prev_hash )

Genesis block concept:
    The very first block in the chain has no predecessor, so we use a
    well-known sentinel value — 64 zeros — as its "prev_hash".
    Every subsequent block's prev_hash equals the block_hash of the block
    that came immediately before it, forming an unbroken chain.
    Altering any field in any certificate will produce a different hash and
    break the chain, making tampering immediately detectable.
"""

import hashlib
from db_connect import get_connection

# Sentinel used when there are no prior blocks in the chain (the genesis case).
GENESIS_HASH = "0" * 64


def get_last_hash(cursor) -> str:
    """Return the block_hash of the most recently inserted ledger block,
    or GENESIS_HASH if no blocks exist yet."""
    cursor.execute(
        "SELECT block_hash FROM ledger_blocks ORDER BY block_id DESC LIMIT 1;"
    )
    result = cursor.fetchone()
    return result[0] if result else GENESIS_HASH


def build_hash_input(student_id, institution_id, course_name, grade, issue_date, prev_hash) -> str:
    """
    Produce a deterministic, canonical string from the certificate's real
    columns so the hash is reproducible at verification time.

    Formatting rules (MUST mirror verify_certificate.py):
      - grade     : always 2 decimal places  (e.g. "8.70"), via f"{float(grade):.2f}"
      - issue_date: always "YYYY-MM-DD HH:MM:SS", via strftime or str() on datetime
      - separator : pipe "|" between every field
    """
    grade_str      = f"{float(grade):.2f}"
    issue_date_str = str(issue_date)[:19]   # "YYYY-MM-DD HH:MM:SS" — trims microseconds
    return f"{student_id}|{institution_id}|{course_name}|{grade_str}|{issue_date_str}|{prev_hash}"


def compute_hash(student_id, institution_id, course_name, grade, issue_date, prev_hash) -> str:
    """Return the SHA-256 hex digest of the canonical certificate string."""
    data = build_hash_input(student_id, institution_id, course_name, grade, issue_date, prev_hash)
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def issue_certificate(student_id, institution_id, course_name, grade, issue_date):
    """
    Insert a certificate row and append a ledger block that hashes the
    certificate's real columns (not a redundant cert_data string).

    Parameters
    ----------
    student_id     : int
    institution_id : int
    course_name    : str
    grade          : float  (stored as DECIMAL(4,2))
    issue_date     : str | datetime  — e.g. "2026-09-01 00:00:00"

    Returns
    -------
    int  — the newly created cert_id
    """
    conn   = get_connection()
    cursor = conn.cursor()

    # Step 1: Insert the certificate (no cert_data column).
    cursor.execute(
        """
        INSERT INTO certificates (student_id, institution_id, course_name, grade, issue_date)
        VALUES (%s, %s, %s, %s, %s)
        """,
        (student_id, institution_id, course_name, grade, issue_date),
    )
    cert_id = cursor.lastrowid

    # Step 2: Get the tip of the chain (genesis if empty).
    prev_hash = get_last_hash(cursor)

    # Step 3: Hash the REAL columns + prev_hash.
    new_hash = compute_hash(student_id, institution_id, course_name, grade, issue_date, prev_hash)

    # Step 4: Append the new block to the ledger.
    cursor.execute(
        """
        INSERT INTO ledger_blocks (cert_id, block_hash, prev_hash)
        VALUES (%s, %s, %s)
        """,
        (cert_id, new_hash, prev_hash),
    )

    conn.commit()
    conn.close()

    print(f"Certificate issued. cert_id={cert_id}, block_hash={new_hash[:16]}...")
    return cert_id


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    issue_certificate(
        student_id=1,
        institution_id=1,
        course_name="B.Tech Computer Science",
        grade=8.70,
        issue_date="2026-09-01 00:00:00",
    )
