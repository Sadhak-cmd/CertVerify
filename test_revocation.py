"""
test_revocation.py
Tests the revocation ledger hash-chain and revocation verification flow:
1. Revocation hash chain calculation (genesis hash for first entry, chaining for subsequent).
2. is_revoked lookup.
3. verify_credential status transition from "valid" to "revoked".
"""

import os
import hashlib
from db_connect import get_connection
from issue_signed_certificate import sign_certificate
from verify_credential import verify_credential
from revoke_certificate import (
    revoke_certificate,
    is_revoked,
    GENESIS_HASH,
    compute_revocation_hash,
)


def test_revocation_lifecycle():
    # Clean up revocations table for a deterministic test
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM revocations;")
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    print("\n--- 1. Testing Genesis Block and Hash Chaining in Revocations ---")
    cert_id_1 = 7
    reason_1 = "Issued in error"
    hash_1 = revoke_certificate(cert_id_1, reason_1)

    expected_hash_1 = compute_revocation_hash(cert_id_1, reason_1, GENESIS_HASH)
    assert hash_1 == expected_hash_1, f"Expected {expected_hash_1}, got {hash_1}"
    print(f"✓ First entry correctly chained from GENESIS_HASH ({GENESIS_HASH[:8]}...).")

    # Second revocation record
    cert_id_2 = 8
    reason_2 = "Academic misconduct"
    hash_2 = revoke_certificate(cert_id_2, reason_2)

    expected_hash_2 = compute_revocation_hash(cert_id_2, reason_2, hash_1)
    assert hash_2 == expected_hash_2, f"Expected {expected_hash_2}, got {hash_2}"
    print(f"✓ Second entry correctly chained from hash_1 ({hash_1[:8]}...).")

    print("\n--- 2. Testing is_revoked Lookup ---")
    record_1 = is_revoked(cert_id_1)
    assert record_1 is not None, "Expected record_1 to not be None"
    assert record_1.reason == reason_1
    assert record_1[0] == reason_1
    assert record_1["reason"] == reason_1
    print(f"✓ is_revoked({cert_id_1}) found: reason='{record_1.reason}', revoked_at={record_1.revoked_at}")

    record_unrevoked = is_revoked(99999)
    assert record_unrevoked is None, "Expected None for unrevoked cert"
    print("✓ is_revoked for unrevoked cert returns None.")

    print("\n--- 3. Testing verify_credential with Revocation Status ---")
    # Issue credential for cert 8
    sign_certificate(cert_id=8, institution_id=1)
    cred_file_8 = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "credentials",
        "credential_8.json",
    )

    result_8 = verify_credential(cred_file_8)
    print(f"Verification result for revoked cert_id 8: {result_8}")
    assert result_8 == "revoked", f"Expected 'revoked', got '{result_8}'"
    assert result_8.reason == reason_2
    assert result_8.revoked_at is not None
    print(f"✓ Revocation detected: result='{result_8}', reason='{result_8.reason}', revoked_at={result_8.revoked_at}")

    # Issue credential for cert 9 (institution 2) which is NOT revoked
    sign_certificate(cert_id=9, institution_id=2)
    cred_file_9 = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "credentials",
        "credential_9.json",
    )
    result_9 = verify_credential(cred_file_9)
    print(f"Verification result for unrevoked cert_id 9: {result_9}")
    assert result_9 == "valid", f"Expected 'valid', got '{result_9}'"
    print("✓ Unrevoked certificate verified as 'valid'.")

    # Now revoke cert 9 and verify it transitions to 'revoked'
    print("\nRevoking cert_id 9...")
    revoke_certificate(cert_id=9, reason="Administrative correction")
    result_9_after = verify_credential(cred_file_9)
    print(f"Verification result after revocation: {result_9_after}")
    assert result_9_after == "revoked"
    assert result_9_after.reason == "Administrative correction"
    print("✓ Certificate 9 transitioned from 'valid' to 'revoked' seamlessly.")


if __name__ == "__main__":
    test_revocation_lifecycle()
    print("\nAll revocation tests passed successfully!")

