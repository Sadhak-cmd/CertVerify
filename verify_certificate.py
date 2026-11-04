"""
verify_certificate.py
Verifies a certificate's integrity by recomputing its hash from the REAL
certificate columns and comparing it to what was recorded in ledger_blocks.

Because the hash is computed from (student_id, institution_id, course_name,
grade, issue_date, prev_hash) — the actual stored columns — any direct edit
to those columns in MySQL will produce a different hash and be caught here.

Genesis block concept (see issue_certificate.py for details):
    The sentinel prev_hash "000...0" (64 zeros) is used for the first block
    in the chain. All subsequent blocks reference their predecessor's hash.
"""

import hashlib
from db_connect import get_connection
from issue_certificate import build_hash_input   # reuse the SAME canonical formatter


def verify_certificate(cert_id: int) -> bool:
    """
    Pull the current column values from `certificates`, recompute the hash
    using the prev_hash stored in `ledger_blocks`, and compare to stored
    block_hash.

    Returns True if VALID, False if TAMPERED or not found.
    """
    conn   = get_connection()
    cursor = conn.cursor()

    # ── 1. Fetch the current, live column values from certificates ──────────
    cursor.execute(
        """
        SELECT student_id, institution_id, course_name, grade, issue_date
        FROM   certificates
        WHERE  cert_id = %s;
        """,
        (cert_id,),
    )
    row = cursor.fetchone()
    if not row:
        print(f"NOT FOUND: No certificate with cert_id={cert_id}.")
        conn.close()
        return False

    student_id, institution_id, course_name, grade, issue_date = row

    # ── 2. Fetch the stored hashes from ledger_blocks ───────────────────────
    cursor.execute(
        """
        SELECT block_hash, prev_hash
        FROM   ledger_blocks
        WHERE  cert_id = %s;
        """,
        (cert_id,),
    )
    block = cursor.fetchone()
    if not block:
        print(f"NOT FOUND: cert_id={cert_id} has no ledger entry — was it ever issued?")
        conn.close()
        return False

    stored_hash, prev_hash = block
    conn.close()

    # ── 3. Recompute hash from the SAME formula used at issuance ────────────
    #
    # CRITICAL: formatting must be bit-for-bit identical to issue_certificate.py.
    # build_hash_input() is imported directly from that module to guarantee this.
    #
    # MySQL returns grade as decimal.Decimal and issue_date as datetime.datetime;
    # build_hash_input() converts both to strings in a fixed, stable format.
    recomputed_hash = hashlib.sha256(
        build_hash_input(
            student_id, institution_id, course_name, grade, issue_date, prev_hash
        ).encode("utf-8")
    ).hexdigest()

    # ── 4. Compare ──────────────────────────────────────────────────────────
    if recomputed_hash == stored_hash:
        print(f"VALID: cert_id={cert_id} — data matches its recorded hash. ✓")
        return True
    else:
        print(f"TAMPERED: cert_id={cert_id} — current data does NOT match the recorded hash! ✗")
        print(f"  Stored hash    : {stored_hash}")
        print(f"  Recomputed hash: {recomputed_hash}")
        return False


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    verify_certificate(10)
