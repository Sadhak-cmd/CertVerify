"""
test_signed_credential.py
Tests issuance and verification of digitally signed credentials:
- Valid credential verification
- Tamper detection (modified grade, course, signature)
- Unknown institution detection
- Database record insertion verification
"""

import os
import json
import tempfile
from db_connect import get_connection
from issue_signed_certificate import sign_certificate
from verify_credential import verify_credential


def test_issue_and_verify_credential():
    cert_id = 11
    institution_id = 1

    print(f"\n1. Signing certificate {cert_id} for institution {institution_id}...")
    package = sign_certificate(cert_id, institution_id)

    assert package is not None, "Failed to return credential package."
    assert package["institution_id"] == institution_id
    assert "signature" in package
    assert "certificate" in package

    cred_file = os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "credentials",
        f"credential_{cert_id}.json",
    )
    assert os.path.exists(cred_file), f"File {cred_file} does not exist."

    # Verify database insertion in credentials table
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM credentials WHERE cert_id = %s;", (cert_id,))
        rows = cursor.fetchall()
        assert len(rows) > 0, f"No record found in credentials table for cert_id={cert_id}"
        assert rows[-1]["signature"] == package["signature"]
    finally:
        cursor.close()
        conn.close()
    print("✓ Credentials table record confirmed.")

    # 2. Verify legitimate credential
    print("2. Verifying legitimate credential file...")
    result = verify_credential(cred_file)
    print(f"Result: {result}")
    assert result == "valid", f"Expected 'valid', got '{result}'"
    print("✓ Legitimate credential verified as 'valid'.")

    # 3. Verify tampered grade detection
    print("3. Testing tamper detection on modified grade...")
    with open(cred_file, "r") as f:
        tampered_pkg = json.load(f)
    tampered_pkg["certificate"]["grade"] = "10.00"

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump(tampered_pkg, tf)
        tampered_path = tf.name

    try:
        res_tampered = verify_credential(tampered_path)
        print(f"Result for modified grade: {res_tampered}")
        assert res_tampered == "invalid", f"Expected 'invalid', got '{res_tampered}'"
        print("✓ Tampered grade correctly detected as 'invalid'.")
    finally:
        os.remove(tampered_path)

    # 4. Verify tampered signature detection
    print("4. Testing tamper detection on modified signature...")
    with open(cred_file, "r") as f:
        tampered_sig_pkg = json.load(f)
    # Mutate the base64 signature string
    orig_sig = tampered_sig_pkg["signature"]
    mutated_char = "A" if orig_sig[10] != "A" else "B"
    tampered_sig_pkg["signature"] = orig_sig[:10] + mutated_char + orig_sig[11:]

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump(tampered_sig_pkg, tf)
        tampered_sig_path = tf.name

    try:
        res_tampered_sig = verify_credential(tampered_sig_path)
        print(f"Result for modified signature: {res_tampered_sig}")
        assert res_tampered_sig == "invalid", f"Expected 'invalid', got '{res_tampered_sig}'"
        print("✓ Tampered signature correctly detected as 'invalid'.")
    finally:
        os.remove(tampered_sig_path)

    # 5. Verify unknown institution detection
    print("5. Testing unknown institution detection...")
    with open(cred_file, "r") as f:
        unknown_inst_pkg = json.load(f)
    unknown_inst_pkg["institution_id"] = 999999

    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as tf:
        json.dump(unknown_inst_pkg, tf)
        unknown_inst_path = tf.name

    try:
        res_unknown = verify_credential(unknown_inst_path)
        print(f"Result for unknown institution: {res_unknown}")
        assert res_unknown == "unknown_institution", f"Expected 'unknown_institution', got '{res_unknown}'"
        print("✓ Unknown institution correctly detected as 'unknown_institution'.")
    finally:
        os.remove(unknown_inst_path)


if __name__ == "__main__":
    test_issue_and_verify_credential()
    print("\nAll credential signing and verification tests passed successfully!")

