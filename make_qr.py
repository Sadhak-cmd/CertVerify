"""
make_qr.py
Generates QR codes for digital credentials to facilitate the hackathon holder wallet demo.

Encodes the full JSON payload directly if within safe limits (~2900 bytes).
If the payload exceeds capacity, falls back to a reference pointer (e.g. 'cert:{cert_id}')
with an explanatory warning.
"""

import os
import json
import qrcode

SAFE_QR_CAPACITY_BYTES = 2900


def generate_qr(credential_json_path: str) -> str:
    """
    Generate a QR code image from a credential JSON package.

    Parameters
    ----------
    credential_json_path : str
        Path to the credential JSON file (e.g. 'credentials/credential_7.json').

    Returns
    -------
    str
        File path of the generated QR code PNG.
    """
    # Resolve file path if only a filename or relative path was passed
    if not os.path.exists(credential_json_path):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        alt_path = os.path.join(base_dir, "credentials", credential_json_path)
        if os.path.exists(alt_path):
            credential_json_path = alt_path
        else:
            raise FileNotFoundError(f"Credential file not found at: {credential_json_path}")

    with open(credential_json_path, "r", encoding="utf-8") as f:
        data = f.read()

    # Parse JSON to extract cert_id for fallback reference
    try:
        package = json.loads(data)
        cert_id = package.get("certificate", {}).get("cert_id")
        if cert_id is None:
            cert_id = package.get("cert_id", "unknown")
    except Exception:
        cert_id = "unknown"

    encoded_bytes = data.encode("utf-8")

    # Check payload size against safe QR limit
    if len(encoded_bytes) > SAFE_QR_CAPACITY_BYTES:
        payload_to_encode = f"cert:{cert_id}"
        print(
            f"[Warning] Credential data ({len(encoded_bytes)} bytes) exceeds safe QR capacity "
            f"({SAFE_QR_CAPACITY_BYTES} bytes). Encoding reference '{payload_to_encode}' instead.\n"
            f"Note: In a production deployment, a reference-based lookup or holder endpoint "
            f"would be used to fetch the full credential."
        )
    else:
        payload_to_encode = data

    # Generate QR code
    img = qrcode.make(payload_to_encode)

    base, _ = os.path.splitext(credential_json_path)
    out_path = f"{base}_qr.png"
    img.save(out_path)

    print(f"QR code successfully generated and saved to {out_path}")
    return out_path


if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "credentials/credential_7.json"
    generate_qr(target)

