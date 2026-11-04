"""
key_manager.py
Manages RSA key pairs for institutions in the certificate verification system.

Ensures idempotent key retrieval and creation:
- Loads existing keys from disk/DB if already generated.
- Generates and stores new 2048-bit RSA keys if not present.
"""

import os
from typing import Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from db_connect import get_connection

__all__ = ["get_or_create_institution_keys"]


def get_or_create_institution_keys(institution_id: int) -> Tuple[rsa.RSAPrivateKey, str]:
    """
    Retrieve existing RSA keys for an institution, or generate and store a new key pair.

    Behavior:
    1. Check if keys/institution_{institution_id}_private.pem already exists on disk.
    2. If it exists: load it, read the institution's public_key column from the
       institutions table via get_connection(), and return both. Does NOT regenerate
       or touch the existing file.
    3. If it does NOT exist: generate a new 2048-bit RSA key pair, save the private
       key as PEM to keys/institution_{institution_id}_private.pem, update the
       institutions table's public_key column with the new public key PEM, and return both.
    4. Automatically creates the keys/ directory if it does not exist.

    Parameters
    ----------
    institution_id : int
        The unique ID of the institution.

    Returns
    -------
    tuple: (private_key_object, public_key_pem_string)
        - private_key_object: RSAPrivateKey instance
        - public_key_pem_string: PEM-formatted public key string
    """
    institution_id = int(institution_id)
    base_dir = os.path.dirname(os.path.abspath(__file__))
    keys_dir = os.path.join(base_dir, "keys")
    os.makedirs(keys_dir, exist_ok=True)

    key_filename = f"institution_{institution_id}_private.pem"
    key_path = os.path.join(keys_dir, key_filename)

    # 1 & 2: Check if private key already exists on disk
    if os.path.exists(key_path):
        print(f"[KeyManager] Loaded existing keys for institution_id={institution_id} from {key_path}")
        with open(key_path, "rb") as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
            )

        conn = get_connection()
        try:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT public_key FROM institutions WHERE institution_id = %s;",
                (institution_id,),
            )
            row = cursor.fetchone()
            if not row:
                raise ValueError(f"Institution with ID {institution_id} not found in database.")

            public_key_pem = row[0]
            if isinstance(public_key_pem, bytes):
                public_key_pem = public_key_pem.decode("utf-8")

            # Fallback sync if DB public_key was empty/NULL
            if not public_key_pem:
                derived_public_key = private_key.public_key()
                public_key_pem = derived_public_key.public_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo,
                ).decode("utf-8")
                cursor.execute(
                    "UPDATE institutions SET public_key = %s WHERE institution_id = %s;",
                    (public_key_pem, institution_id),
                )
                conn.commit()
        finally:
            cursor.close()
            conn.close()

        return private_key, public_key_pem

    # 3: Key does NOT exist on disk -> generate a new 2048-bit RSA key pair
    print(f"[KeyManager] Generated new keys for institution_id={institution_id}")

    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    # Serialize private key to PEM
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Serialize public key to PEM string
    public_pem_str = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # Verify institution exists and update public_key in DB
    conn = get_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            "SELECT institution_id FROM institutions WHERE institution_id = %s;",
            (institution_id,),
        )
        if not cursor.fetchone():
            raise ValueError(f"Institution with ID {institution_id} not found in database.")

        cursor.execute(
            "UPDATE institutions SET public_key = %s WHERE institution_id = %s;",
            (public_pem_str, institution_id),
        )
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    # Save private key to PEM file
    with open(key_path, "wb") as f:
        f.write(private_pem)

    return private_key, public_pem_str

