"""
issue_signed_certificate.py
Signs a certificate using the issuing institution's RSA private key and produces
a portable, tamper-evident digital credential package.

Credential format (version 2)
-----------------------------
{
  "version": 2,
  "certificate": { cert_id, institution_id, course_name, grade, issue_date, student_id, [student_name] },
  "salts":       { <field>: random salt }          # lets the holder reveal a field
  "commitments": { <field>: sha256(salt|field|value) }   # what the institution actually signs
  "signature":   base64 RSA-PSS over canonical {cert_id, institution_id, commitments}
  "institution_id": 1,
  "key_id": "<sha256 fingerprint of the institution public key>"
}
The full file is the holder's PRIVATE copy. The holder shares a presentation.py "proof" that
reveals only chosen fields; the signature still verifies because it covers the commitments.
"""

import os
import json
import base64
from typing import Any, Dict, Optional
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from db_connect import get_connection
from key_manager import get_or_create_institution_keys
from canonical import (CORE_FIELDS, canonical_cert_dict, field_commitment, make_salt,
                       signing_payload)
from trust_store import key_id_from_public_pem


def _student_name(cursor, student_id) -> Optional[str]:
    """Best-effort: the holder's name, kept as a HIDDEN-by-default committed field."""
    try:
        cursor.execute("SELECT * FROM students WHERE student_id = %s;", (student_id,))
        row = cursor.fetchone()
        if row:
            for col in ("student_name", "full_name", "name"):
                if row.get(col):
                    return str(row[col])
    except Exception:
        pass
    return None


def sign_certificate(cert_id: int, institution_id: int) -> Dict[str, Any]:
    """
    Sign a certificate and create a portable credential package.

    Parameters
    ----------
    cert_id : int
        The certificate ID to sign.
    institution_id : int
        The institution issuing the signature.

    Returns
    -------
    dict
        The portable (version 2) credential package.
    """
    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT * FROM certificates WHERE cert_id = %s;", (cert_id,))
        cert = cursor.fetchone()
        if not cert:
            raise ValueError(f"Certificate with cert_id={cert_id} not found in database.")

        cert_fields = canonical_cert_dict(cert)
        if int(cert_fields.get("institution_id")) != int(institution_id):
            raise ValueError(
                f"Certificate {cert_id} belongs to institution {cert_fields.get('institution_id')}, "
                f"not {institution_id}."
            )
        name = _student_name(cursor, cert_fields.get("student_id"))
        if name:
            cert_fields["student_name"] = name

        # Get or create institution signing keys (handles both first-time and repeat cases)
        private_key, _ = get_or_create_institution_keys(institution_id)
        public_pem = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        # Commit to every non-core field with its own random salt
        salts = {f: make_salt() for f in cert_fields if f not in CORE_FIELDS}
        commitments = {f: field_commitment(f, cert_fields[f], salts[f]) for f in salts}

        # Sign using RSA-PSS with SHA-256 over the commitments + core fields
        payload = signing_payload(cert_fields["cert_id"], cert_fields["institution_id"], commitments)
        signature = private_key.sign(
            payload.encode("utf-8"),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH,
            ),
            hashes.SHA256(),
        )
        signature_b64 = base64.b64encode(signature).decode("utf-8")

        # Record signature in credentials table
        cursor.execute(
            """
            INSERT INTO credentials (cert_id, signature, issued_at)
            VALUES (%s, %s, NOW());
            """,
            (cert_id, signature_b64),
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    # Build the portable credential package
    credential_package = {
        "version": 2,
        "certificate": cert_fields,
        "salts": salts,
        "commitments": commitments,
        "signature": signature_b64,
        "institution_id": institution_id,
        "key_id": key_id_from_public_pem(public_pem),
    }

    base_dir = os.path.dirname(os.path.abspath(__file__))
    credentials_dir = os.path.join(base_dir, "credentials")
    os.makedirs(credentials_dir, exist_ok=True)
    credential_file_path = os.path.join(credentials_dir, f"credential_{cert_id}.json")

    with open(credential_file_path, "w", encoding="utf-8") as f:
        json.dump(credential_package, f, indent=2)

    print(f"Certificate {cert_id} signed. Credential package saved to {credential_file_path}")
    return credential_package


if __name__ == "__main__":
    # Example usage: sign certificate 7 for institution 1
    pkg = sign_certificate(cert_id=7, institution_id=1)
    print("Signed credential package generated successfully.")
