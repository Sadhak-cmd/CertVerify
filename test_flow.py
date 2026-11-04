import json, os, shutil
from db_connect import get_connection
from key_manager import get_or_create_institution_keys
from issue_signed_certificate import sign_certificate
from verify_credential import verify_credential
from revoke_certificate import revoke_certificate, is_revoked
from make_qr import generate_qr
import publisher

def new_cert():
    """Insert a fresh certificate so each test is independent."""
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""INSERT INTO certificates
        (student_id, institution_id, course_name, grade, issue_date)
        VALUES (1, 1, 'B.Tech Computer Science', 8.70, NOW())""")
    conn.commit(); cid = cur.lastrowid; conn.close()
    return cid

def check(name, ok):
    print(("PASS  " if ok else "FAIL  ") + name)

# 1. Key idempotency
get_or_create_institution_keys(1)
p = "keys/institution_1_private.pem"
before = open(p, "rb").read()
get_or_create_institution_keys(1)
check("keys unchanged on second call", before == open(p, "rb").read())

# 1b. Institution publishes its key info + signed revocation list; the verifier pins the key and
#     downloads the list (this is the one-time onboarding step: python publisher.py --trust --sync)
publisher.publish_all(1, trust=True, sync=True)

# 2. Sign + verify a good certificate
c1 = new_cert()
sign_certificate(c1, 1)
path1 = f"credentials/credential_{c1}.json"
check("credential file created", os.path.exists(path1))
check("valid cert verifies", "valid" in str(verify_credential(path1)).lower()
      and "invalid" not in str(verify_credential(path1)).lower())

# 3. Tamper with the JSON file (change the grade) -> must be invalid
tampered = f"credentials/tampered_{c1}.json"
pkg = json.load(open(path1))
pkg["certificate"]["grade"] = "9.90"
json.dump(pkg, open(tampered, "w"))
check("tampered grade is rejected", "invalid" in str(verify_credential(tampered)).lower())

# 4. Swap in a signature from a different certificate -> must be invalid
c2 = new_cert(); sign_certificate(c2, 1)
pkg2 = json.load(open(f"credentials/credential_{c2}.json"))
pkg["certificate"]["grade"] = pkg2["certificate"]["grade"]
pkg["signature"] = pkg2["signature"]
json.dump(pkg, open(tampered, "w"))
check("swapped signature is rejected", "invalid" in str(verify_credential(tampered)).lower())

# 5. Revocation flips the result
check("not revoked before", not is_revoked(c2))
revoke_certificate(c2, "test revocation")
check("revoked after", bool(is_revoked(c2)))
# The institution publishes a new signed revocation list; the verifier downloads it.
publisher.publish_all(1, sync=True)
check("verify now says revoked",
      "revoked" in str(verify_credential(f"credentials/credential_{c2}.json")).lower())

# 6. Original cert (c1) is unaffected by revoking c2
check("other cert still valid", "invalid" not in str(verify_credential(path1)).lower()
      and "revoked" not in str(verify_credential(path1)).lower())

# 7. Revocation hash chain links correctly
conn = get_connection(); cur = conn.cursor()
cur.execute("SELECT revocation_hash, prev_hash FROM revocations ORDER BY revocation_id")
rows = cur.fetchall(); conn.close()
chain_ok = all(rows[i][1] == rows[i-1][0] for i in range(1, len(rows)))
check("revocation chain links (prev_hash == previous hash)", chain_ok)

# 8. QR code
generate_qr(path1)
check("QR image created", os.path.exists(path1.replace(".json", "_qr.png")))

os.remove(tampered)
