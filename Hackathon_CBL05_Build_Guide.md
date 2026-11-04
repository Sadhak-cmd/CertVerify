# CBL-05: Academic Certificate Verification Without Central Lookup
## Build Guide — Continuing From Your DBMS Project Setup

---

## Part 0: How This Relates To Your DBMS Project

You already have: MySQL installed and running, VS Code set up, Python with `mysql-connector-python` installed, a working `certificates` table, and a tested SHA-256 hash-chain (issue/verify scripts) in `ledger_blocks`.

**What carries over directly:** your hash-chain logic is a real, working example of a "ledger design" — you'll reuse it almost as-is for the revocation log in this project, and it becomes first-hand evidence for deliverable #4 (the written comparison).

**What's new and missing:** your current system can only prove "this data hasn't changed since it was written to my database" — it says nothing about *who* wrote it, and a verifier has to trust your database directly. That's fine for a course project, but this hackathon's core requirement — "verify issuance in seconds, without a central lookup" — specifically needs **digital signatures**, which let a verifier confirm authenticity using only a public key they fetched once, with no live database query needed per verification. You also need an entirely new **OCR legacy-certificate matching** component, which your DBMS project never touched.

---

## Part 1: New Tools to Install

You already have Python, MySQL, MySQL Workbench, and VS Code. Add these:

### Step 1 — Install new Python packages

```bash
pip install cryptography qrcode[pil] pytesseract pillow opencv-python
```

What each one does:
- `cryptography` — generates RSA key pairs and handles signing/verifying (this is your digital signature engine)
- `qrcode[pil]` — generates QR codes so a credential can be shared/scanned, not just emailed as a file
- `pytesseract` — Python wrapper for Tesseract OCR, which reads text out of certificate images
- `pillow` — image handling (opening/processing uploaded certificate photos)
- `opencv-python` — optional but recommended; used to clean up photos before OCR (deskewing, contrast adjustment) since raw phone photos of certificates often OCR poorly otherwise

### Step 2 — Install the Tesseract OCR engine itself

**Important distinction:** `pytesseract` is just a Python wrapper — it calls out to the actual Tesseract program, which is separate system software you need to install:

- **Windows:** download the installer from the UB-Mannheim Tesseract build (search "tesseract ocr windows installer UB Mannheim"), run it, and note the install path (usually `C:\Program Files\Tesseract-OCR\tesseract.exe`) — you'll need to point `pytesseract` to this path in your script.
- **Mac:** `brew install tesseract`
- **Linux:** `sudo apt install tesseract-ocr`

Test it worked: open a terminal and run `tesseract --version` — if it prints a version number, you're set.

---

## Part 2: Updated Schema (Additions to What You Have)

Open MySQL Workbench, same `cert_verification` database, and add these:

```sql
-- Add a public key column to institutions (their private key stays OFF the database, see Part 3)
ALTER TABLE institutions ADD COLUMN public_key TEXT;

-- Digitally signed credential record (separate from your plain certificates table)
CREATE TABLE credentials (
    credential_id INT PRIMARY KEY AUTO_INCREMENT,
    cert_id INT NOT NULL,
    signature TEXT NOT NULL,          -- base64-encoded RSA signature of the certificate's canonical data
    issued_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cert_id) REFERENCES certificates(cert_id)
);

-- Revocation ledger (reuses your Layer-1 hash-chain pattern)
CREATE TABLE revocations (
    revocation_id INT PRIMARY KEY AUTO_INCREMENT,
    cert_id INT NOT NULL,
    reason VARCHAR(255),
    revoked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    revocation_hash CHAR(64) NOT NULL,
    prev_hash CHAR(64) NOT NULL,
    FOREIGN KEY (cert_id) REFERENCES certificates(cert_id)
);

-- The institution's own digitized historical records, used as ground truth for legacy paper-certificate matching
CREATE TABLE legacy_records (
    legacy_id INT PRIMARY KEY AUTO_INCREMENT,
    institution_id INT NOT NULL,
    student_name VARCHAR(255),
    roll_number VARCHAR(50),
    course_name VARCHAR(255),
    grade DECIMAL(4,2),
    issue_date DATE,
    FOREIGN KEY (institution_id) REFERENCES institutions(institution_id)
);
```

**Why a separate `credentials` table instead of reusing `ledger_blocks`?** Your DBMS project's hash-chain proves internal consistency within your own database. This project's `credentials` table proves something stronger and different: that a specific institution, holding a specific private key, actually authorized this exact certificate — provable by anyone holding the institution's public key, with no access to your database at all. They're complementary, not redundant, and you'll want to clearly explain this distinction in your written comparison (Part 7).

---

## Part 3: Issuer Side — Keys and Signing

### Step 3 — Generate an institution's key pair

Create `generate_keys.py`:

```python
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
    generate_institution_keys(1, "ABC University")
```

Run this once per institution. **The private key file in `keys/` is the institution's secret — in a real system it would live in a hardware security module or secrets vault, never on a shared machine.** For your demo, just keep it local and don't commit it to GitHub (add `keys/` to a `.gitignore` file).

### Step 4 — Sign a certificate at issuance

Create `issue_signed_certificate.py`. The key idea: convert the certificate's data into one consistent, canonical string format (same lesson as your DBMS project's hash-chain bug — formatting must be deterministic), then sign that string.

```python
import json
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from db_connect import get_connection

def canonical_cert_data(cert):
    # Deterministic, sorted-key JSON — same string every time for the same data
    return json.dumps(cert, sort_keys=True, default=str)

def sign_certificate(cert_id, institution_id):
    conn = get_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM certificates WHERE cert_id = %s;", (cert_id,))
    cert = cursor.fetchone()

    data_string = canonical_cert_data(cert)

    # Load the institution's private key
    with open(f"keys/institution_{institution_id}_private.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    signature = private_key.sign(
        data_string.encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256()
    )
    signature_b64 = base64.b64encode(signature).decode()

    cursor.execute("""
        INSERT INTO credentials (cert_id, signature) VALUES (%s, %s)
    """, (cert_id, signature_b64))
    conn.commit()
    conn.close()

    # Build the portable credential package — this is what the holder actually receives
    credential_package = {
        "certificate": cert,
        "signature": signature_b64,
        "institution_id": institution_id
    }
    with open(f"credential_{cert_id}.json", "w") as f:
        json.dump(credential_package, f, indent=2, default=str)

    print(f"Certificate {cert_id} signed. Credential package saved as credential_{cert_id}.json")
    return credential_package

if __name__ == "__main__":
    sign_certificate(cert_id=1, institution_id=1)
```

This JSON file is effectively the certificate's digital, tamper-evident form — it contains the data, the signature, and which institution to check it against. **This file (or a QR code encoding it) is your "holder wallet" artifact** — see Part 4.

---

## Part 4: Holder Wallet (Keep This Simple)

For a hackathon demo, don't over-build this. A reasonable, honest scope: the "wallet" is wherever the holder keeps their `credential_*.json` file(s) — downloaded from the issuer, and presentable to a verifier as a file upload or as a QR code.

### Step 5 — Generate a QR code for a credential

Create `make_qr.py`:

```python
import qrcode
import json

def generate_qr(credential_json_path):
    with open(credential_json_path) as f:
        data = f.read()

    # If the credential is small enough, encode it directly.
    # QR codes have a data limit (~2900 bytes for alphanumeric) — if your credential
    # JSON is larger, encode a short reference ID instead and have the verifier
    # fetch the full JSON from wherever the holder is hosting it.
    img = qrcode.make(data)
    out_path = credential_json_path.replace(".json", "_qr.png")
    img.save(out_path)
    print(f"QR code saved to {out_path}")

if __name__ == "__main__":
    generate_qr("credential_1.json")
```

For your demo, a simple Flask page where a "holder" logs in (by roll number, say) and sees a download button for their `credential_*.json` and a displayed QR code is enough to satisfy "holder wallet" — you don't need persistent accounts or a mobile app for a hackathon demo, and it's fine to say so explicitly when presenting: "the wallet is intentionally lightweight for this demo; a production version would be a mobile app with secure local storage."

---

## Part 5: Verifier — Signature + Revocation Check (No Central Lookup)

This is the core of the "without a central lookup" requirement. Walk through it carefully, because it's the part judges will probe hardest.

### Step 6 — Build the verifier

Create `verify_credential.py`:

```python
import json
import base64
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.exceptions import InvalidSignature
from db_connect import get_connection

def canonical_cert_data(cert):
    return json.dumps(cert, sort_keys=True, default=str)

def get_institution_public_key(institution_id):
    # This is the ONLY database interaction needed to verify ANY number of
    # certificates from this institution. It's not a per-certificate lookup —
    # a real verifier would cache this after the first fetch.
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT public_key FROM institutions WHERE institution_id = %s;", (institution_id,))
    result = cursor.fetchone()
    conn.close()
    return result[0] if result else None

def is_revoked(cert_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT reason, revoked_at FROM revocations WHERE cert_id = %s ORDER BY revocation_id DESC LIMIT 1;", (cert_id,))
    result = cursor.fetchone()
    conn.close()
    return result  # None if not revoked, else (reason, revoked_at)

def verify_credential(credential_json_path):
    with open(credential_json_path) as f:
        package = json.load(f)

    cert = package["certificate"]
    signature_b64 = package["signature"]
    institution_id = package["institution_id"]

    public_key_pem = get_institution_public_key(institution_id)
    if not public_key_pem:
        print("UNKNOWN INSTITUTION — cannot verify.")
        return "unknown_institution"

    public_key = serialization.load_pem_public_key(public_key_pem.encode())
    data_string = canonical_cert_data(cert)
    signature = base64.b64decode(signature_b64)

    try:
        public_key.verify(
            signature,
            data_string.encode(),
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256()
        )
    except InvalidSignature:
        print("INVALID SIGNATURE — this certificate was tampered with or was never signed by this institution.")
        return "invalid"

    # Signature checks out — now check revocation status (lightweight, separate from personal data)
    revoked = is_revoked(cert["cert_id"])
    if revoked:
        reason, revoked_at = revoked
        print(f"REVOKED on {revoked_at}. Reason: {reason}")
        return "revoked"

    print("VALID. Signature verified, not revoked.")
    return "valid"

if __name__ == "__main__":
    verify_credential("credential_1.json")
```

**Why this satisfies "without a central lookup":** the heavy, per-verification work (checking the signature) happens entirely offline using a public key the verifier already has — no network call, no institution involvement, no personal data exchanged. The only database interaction left is a tiny revocation-status check on a cert ID, which is a yes/no flag, not a personal-data lookup. This is the architectural point you'll want to articulate clearly in both your demo narration and your written comparison.

---

## Part 6: Revocation (Reusing Your DBMS Hash-Chain Logic)

### Step 7 — Build the revocation ledger

This is almost identical to your DBMS project's `issue_certificate.py` hash-chaining logic — just applied to revocation events instead of certificates. Create `revoke_certificate.py`:

```python
import hashlib
from db_connect import get_connection

GENESIS_HASH = "0" * 64

def get_last_revocation_hash(cursor):
    cursor.execute("SELECT revocation_hash FROM revocations ORDER BY revocation_id DESC LIMIT 1;")
    result = cursor.fetchone()
    return result[0] if result else GENESIS_HASH

def revoke_certificate(cert_id, reason):
    conn = get_connection()
    cursor = conn.cursor()

    prev_hash = get_last_revocation_hash(cursor)
    combined = f"{cert_id}|{reason}|{prev_hash}"
    new_hash = hashlib.sha256(combined.encode()).hexdigest()

    cursor.execute("""
        INSERT INTO revocations (cert_id, reason, revocation_hash, prev_hash)
        VALUES (%s, %s, %s, %s)
    """, (cert_id, reason, new_hash, prev_hash))

    conn.commit()
    conn.close()
    print(f"Certificate {cert_id} revoked. Reason: {reason}")

if __name__ == "__main__":
    revoke_certificate(cert_id=1, reason="Issued in error")
```

**For your live demo of the revocation test:**
1. Run `verify_credential.py` on `credential_1.json` → shows VALID.
2. Run `revoke_certificate.py` to revoke cert_id 1.
3. Run `verify_credential.py` on the exact same file again → now shows REVOKED.

This is a clean, visual, judge-friendly demo moment — practice it.

---

## Part 7: Legacy Paper Certificate Check (OCR)

### Step 8 — Seed some legacy records

In MySQL Workbench, insert a few rows simulating an institution's old digitized records:

```sql
INSERT INTO legacy_records (institution_id, student_name, roll_number, course_name, grade, issue_date)
VALUES (1, 'Riya Sharma', 'CS2019045', 'B.Tech Computer Science', 8.4, '2019-06-15');
```

### Step 9 — Build the OCR matcher

Create `legacy_check.py`. **Practical tip:** OCR accuracy on messy phone photos of real certificates is genuinely difficult — for a reliable hackathon demo, prepare a clean, consistently-formatted sample certificate image (generate one yourself as a simple template with clear printed text) rather than relying on OCR to handle arbitrary real-world documents. Mention this limitation honestly when you present.

```python
import pytesseract
from PIL import Image
import re
from db_connect import get_connection

# If on Windows, uncomment and set this to your install path:
# pytesseract.pytesseract.tesseract_cmd = r"C:\Program Files\Tesseract-OCR\tesseract.exe"

def extract_text(image_path):
    img = Image.open(image_path)
    return pytesseract.image_to_string(img)

def extract_fields(raw_text):
    # Basic heuristic extraction — tune these patterns to match your sample certificate's layout
    fields = {}
    roll_match = re.search(r"Roll\s*(?:No\.?|Number)?\s*[:\-]?\s*([A-Z0-9]+)", raw_text, re.IGNORECASE)
    name_match = re.search(r"Name\s*[:\-]?\s*([A-Za-z ]+)", raw_text, re.IGNORECASE)
    grade_match = re.search(r"(?:Grade|CGPA|GPA)\s*[:\-]?\s*([\d.]+)", raw_text, re.IGNORECASE)

    if roll_match: fields["roll_number"] = roll_match.group(1).strip()
    if name_match: fields["student_name"] = name_match.group(1).strip()
    if grade_match: fields["grade"] = grade_match.group(1).strip()
    return fields

def check_legacy_certificate(image_path, institution_id):
    raw_text = extract_text(image_path)
    extracted = extract_fields(raw_text)

    if "roll_number" not in extracted:
        return {"status": "unreadable", "message": "Could not extract a roll number from the image."}

    conn = get_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT * FROM legacy_records
        WHERE institution_id = %s AND roll_number = %s
    """, (institution_id, extracted["roll_number"]))
    record = cursor.fetchone()
    conn.close()

    if not record:
        return {"status": "forgery_flag", "message": f"No institution record found for roll number {extracted['roll_number']}.", "extracted": extracted}

    mismatches = []
    if "student_name" in extracted and extracted["student_name"].lower() not in record["student_name"].lower():
        mismatches.append("student_name")
    if "grade" in extracted:
        try:
            if abs(float(extracted["grade"]) - float(record["grade"])) > 0.05:
                mismatches.append("grade")
        except ValueError:
            mismatches.append("grade (unparseable)")

    if mismatches:
        return {"status": "forgery_flag", "message": f"Mismatched fields: {', '.join(mismatches)}", "extracted": extracted, "institution_record": record}

    return {"status": "verified", "message": "Matches institution record.", "extracted": extracted, "institution_record": record}

if __name__ == "__main__":
    result = check_legacy_certificate("sample_legacy_cert.jpg", institution_id=1)
    print(result)
```

This is intentionally a simple field-matching approach rather than full document-layout verification — appropriate and defensible for a hackathon demo, and you can explicitly mention computer-vision template matching (comparing the document's visual layout against a known institutional template) as a natural future extension, same as the stretch goal from your DBMS project's research.

---

## Part 8: Tying It Together (Minimal Flask App)

For the demo, one Flask app with simple routes for each role is enough:

```
/issuer           -> form to issue + sign a new certificate, triggers issue_signed_certificate.py + sign_certificate.py
/issuer/revoke    -> form to revoke a cert_id, triggers revoke_certificate.py
/holder/<roll_no> -> shows download links / QR codes for that holder's credential(s)
/verifier         -> upload a credential_*.json file, runs verify_credential.py, shows VALID / INVALID / REVOKED
/verifier/legacy  -> upload a certificate image, runs legacy_check.py, shows match result
```

Keep each route thin — just call the scripts above and render the result. Don't spend hackathon time on styling; a judge cares about the flow working end-to-end far more than visual polish.

---

## Part 9: The Written Comparison (Deliverable #4)

This is where your DBMS project pays off directly — you've actually built a ledger-style system (your Layer 1 hash-chain, reused here for revocations), so you can compare it against a signed-registry alternative from genuine implementation experience, not just theory. Structure it around these axes:

| Axis | Ledger design (what you built: hash-chained revocation log) | Signed-registry design (plain table, each entry individually signed) |
|---|---|---|
| **Tamper evidence** | Strong — altering any past entry breaks every hash after it, detectable by anyone with the chain | Weaker — an entry can be silently edited unless each one is individually re-verified against its own signature, and even then a privileged admin could delete and not re-sign |
| **Trust model** | Still relies on one database in your implementation (acknowledge this honestly — true decentralization needs multiple independent nodes) | Explicitly trusts the institution's server; no illusion of decentralization, which is arguably more honest about where trust actually sits |
| **Verification speed/complexity** | Requires walking/checking the chain (or at least the latest hash) to confirm no tampering | Simpler — just verify one signature per entry, independent of chain state |
| **Auditability by third parties** | Strong — the full history is inspectable and self-consistent | Depends entirely on the institution publishing/exposing its signed records; nothing stops silent deletion of a record the institution doesn't publish |
| **Infrastructure cost** | More moving parts (chain state, genesis handling, consistency checks) | Simpler to build and reason about — which is exactly why it's a legitimate, common real-world choice (this is literally how TLS certificates and most real-world PKI systems work) |
| **Best fit** | Scenarios needing a shared, cross-institution audit trail no single party controls | Scenarios where one institution is clearly the sole authority anyway (which, candidly, describes most university-certificate issuance) |

Your honest conclusion can be nuanced rather than declaring one "better" — e.g., argue that for certificate *issuance* a signed registry is arguably sufficient (since there's naturally one authoritative issuer per certificate anyway), while a ledger adds real value specifically for the *revocation log*, where tamper-evidence against a possible later cover-up (e.g., an institution being pressured to quietly un-revoke a fraudulent certificate) is a meaningfully different threat model. This kind of nuanced, evidence-based judgment — rather than "blockchain is better" — is exactly what distinguishes a strong hackathon write-up from a weak one.

---

## Suggested Build Order Given Limited Hackathon Time

1. Schema additions (Part 2) — 15 minutes
2. Key generation + signing (Part 3) — get one certificate issued and signed end-to-end first, before building anything else
3. Verifier (Part 5) — confirm VALID works before moving on
4. Revocation (Part 6) — confirm the VALID → REVOKED flip works; this is your most visually compelling demo moment
5. QR code (Part 4) — quick, makes the demo feel more "real"
6. Legacy OCR check (Part 7) — budget real time here; OCR is the most likely thing to misbehave, so prepare a clean sample image early and test repeatedly
7. Flask wrapper (Part 8) — only once the underlying logic all works standalone
8. Written comparison (Part 9) — write this last, since you'll have real implementation details fresh in mind
