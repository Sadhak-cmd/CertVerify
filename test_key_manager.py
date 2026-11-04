"""
test_key_manager.py
Test suite to verify idempotency of get_or_create_institution_keys.

Verifies:
1. Calling get_or_create_institution_keys multiple times returns identical keys.
2. The private key file's contents and modification time (mtime) on disk are unchanged after the second call.
3. The returned public key matches the database column.
"""

import os
import time
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from db_connect import get_connection
from key_manager import get_or_create_institution_keys


def test_get_or_create_institution_keys_idempotency():
    institution_id = 1
    key_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "keys",
        f"institution_{institution_id}_private.pem",
    )

    # Call 1: May generate or load depending on whether keys exist
    print(f"\n--- Call 1: Initial call for institution_id={institution_id} ---")
    priv_key_1, pub_key_pem_1 = get_or_create_institution_keys(institution_id)

    assert os.path.exists(key_path), f"Expected key file to exist at {key_path}"

    with open(key_path, "rb") as f:
        content_after_first = f.read()
    mtime_after_first = os.path.getmtime(key_path)

    # Pause briefly to ensure any subsequent disk write would register a distinct mtime
    time.sleep(0.1)

    # Call 2: Must load existing keys without modifying the file
    print(f"--- Call 2: Idempotent call for institution_id={institution_id} ---")
    priv_key_2, pub_key_pem_2 = get_or_create_institution_keys(institution_id)

    with open(key_path, "rb") as f:
        content_after_second = f.read()
    mtime_after_second = os.path.getmtime(key_path)

    # Assertions
    # 1. File content unchanged
    assert content_after_first == content_after_second, (
        "FAILED: Private key file contents changed on second call!"
    )

    # 2. File modification time unchanged
    assert mtime_after_first == mtime_after_second, (
        f"FAILED: Private key file modification time changed! "
        f"(first: {mtime_after_first}, second: {mtime_after_second})"
    )

    # 3. Public key strings identical
    assert pub_key_pem_1 == pub_key_pem_2, (
        "FAILED: Returned public key PEM string differed between calls!"
    )

    # 4. Private keys identical (comparing RSA private numbers)
    assert priv_key_1.private_numbers() == priv_key_2.private_numbers(), (
        "FAILED: Private key objects represent different RSA keys!"
    )

    # 5. Database has matching public key
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT public_key FROM institutions WHERE institution_id = %s;",
            (institution_id,),
        )
        row = cursor.fetchone()
        assert row is not None and row[0] == pub_key_pem_2, (
            "FAILED: Database public_key does not match returned public key PEM!"
        )
    finally:
        cursor.close()
        conn.close()

    # 6. Cryptographic functionality: sign with priv_key_2 and verify with pub_key_2
    test_message = b"Idempotency and cryptographic integrity test message"
    signature = priv_key_2.sign(
        test_message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )
    loaded_pub_key = load_pem_public_key(pub_key_pem_2.encode("utf-8"))
    loaded_pub_key.verify(
        signature,
        test_message,
        padding.PKCS1v15(),
        hashes.SHA256(),
    )

    print("\n✓ PASS: Private key file contents are unchanged.")
    print("✓ PASS: Private key file modification time is unchanged.")
    print("✓ PASS: Public key PEM string is identical across calls.")
    print("✓ PASS: Database contains the matching public key.")
    print("✓ PASS: Cryptographic signature successfully verified.")


if __name__ == "__main__":
    
    print("Running test_get_or_create_institution_keys_idempotency()...")
    test_get_or_create_institution_keys_idempotency()
    print("\nAll tests passed successfully!")

