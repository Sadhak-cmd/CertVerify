from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
from db_connect import get_connection

def generate_institution_keys(institution_id, institution_name):
    # Generate a 2048-bit RSA key pair
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()

    # Serialize private key to PEM (keep this OFF the database — simulate secure institutional storage)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key to PEM (this one IS safe to publish/store in the database)
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    os.makedirs("keys", exist_ok=True)
    key_path = f"keys/institution_{institution_id}_private.pem"
    with open(key_path, "wb") as f:
        f.write(private_pem)

    # Store ONLY the public key in MySQL
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE institutions SET public_key = %s WHERE institution_id = %s;",
                   (public_pem.decode(), institution_id))
    conn.commit()
    conn.close()

    print(f"Keys generated for {institution_name}. Private key saved to {key_path} (keep this safe!). Public key stored in DB.")

if __name__ == "__main__":
    generate_institution_keys(1, "Vishwakarma Institute of Information Technology")