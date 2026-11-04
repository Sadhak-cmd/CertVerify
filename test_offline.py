"""
test_offline.py
Proves the DIGITAL verification path needs no central lookup, and checks data minimization.

Phase 1 (database ON):  issue certificates, publish key info + signed revocation list, pin the key.
Phase 2 (database OFF): every database access AND every network connect is made to raise, then
                        the verifier is exercised. If verification touched either, it would crash.

Run:  python test_offline.py        (MySQL must be running for phase 1 only)

For the real-world version of phase 2, also stop MySQL (e.g. `brew services stop mysql`) and
use the Verifier page of the app: it keeps working. Start MySQL again afterwards.
"""

import base64
import copy
import datetime
import json
import os
import shutil
import socket
import sys
import tempfile

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

from db_connect import get_connection
from issue_signed_certificate import sign_certificate
from presentation import create_presentation
from revoke_certificate import revoke_certificate
import publisher
import trust_store
from verify_credential import verify_credential

BASE = os.path.dirname(os.path.abspath(__file__))
os.chdir(BASE)
results = []


def check(name, ok, note=""):
    results.append(bool(ok))
    print(("PASS  " if ok else "FAIL  ") + name + (("   [" + note + "]") if note else ""))


class Blocked(Exception):
    pass


def _blocked(*args, **kwargs):
    raise Blocked("database/network access attempted during verification")


_saved = []


def block_everything():
    """Make any database or network access raise."""
    for mod in list(sys.modules.values()):
        if mod is not None and hasattr(mod, "get_connection"):
            _saved.append((mod, "get_connection", mod.get_connection))
            mod.get_connection = _blocked
    try:
        import mysql.connector as mc
        _saved.append((mc, "connect", mc.connect))
        mc.connect = _blocked
    except ImportError:
        pass
    _saved.append((socket.socket, "connect", socket.socket.connect))
    socket.socket.connect = _blocked


def unblock_everything():
    while _saved:
        obj, attr, original = _saved.pop()
        setattr(obj, attr, original)


def new_cert():
    conn = get_connection(); cur = conn.cursor()
    cur.execute("""INSERT INTO certificates (student_id, institution_id, course_name, grade, issue_date)
                   VALUES (1, 1, 'B.Tech Computer Science', 8.70, NOW())""")
    conn.commit(); cid = cur.lastrowid; conn.close()
    return cid


def status(path, **kw):
    return str(verify_credential(path, **kw))


def dump(obj, path):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
    return path


# =============================================================== PHASE 1 (DB ON)
print("--- Phase 1: setup with the database running ---")
tmp = tempfile.mkdtemp(prefix="certtest_")
publisher.publish_all(1, trust=True, sync=True)
# An older (but genuinely signed) list, kept aside to test rollback protection later.
old_snapshot = os.path.join(tmp, "old_published")
os.makedirs(old_snapshot)
publisher.publish_revocation_snapshot(
    1, out_dir=old_snapshot, now=trust_store.utcnow() - datetime.timedelta(hours=1))

cA, cB = new_cert(), new_cert()
sign_certificate(cA, 1); sign_certificate(cB, 1)
pathA, pathB = "credentials/credential_%d.json" % cA, "credentials/credential_%d.json" % cB
presA = create_presentation(pathA)                      # minimal proof: course + date only
revoke_certificate(cB, "test revocation (offline suite)")
publisher.publish_all(1, sync=True)                      # new signed list -> downloaded by the verifier
check("online: certificate A verifies", status(pathA) == "valid")
check("online: certificate B is revoked", status(pathB) == "revoked")

# ============================================================ PHASE 2 (DB + NETWORK OFF)
print("\n--- Phase 2: database and network BLOCKED ---")
block_everything()
try:
    # 3/4. The core claim
    check("offline: valid credential still verifies", status(pathA) == "valid")
    check("offline: revoked credential still detected (authenticated snapshot)", status(pathB) == "revoked")

    # 5. Tampering
    pkg = json.load(open(pathA)); pkg["certificate"]["grade"] = "9.90"
    check("offline: tampered grade rejected", status(dump(pkg, os.path.join(tmp, "t1.json"))) == "invalid")
    pkg = json.load(open(pathA)); pkg["signature"] = json.load(open(pathB))["signature"]
    check("offline: swapped signature rejected", status(dump(pkg, os.path.join(tmp, "t2.json"))) == "invalid")
    pkg = json.load(open(pathA)); pkg["certificate"]["cert_id"] = cB + 1000
    check("offline: changed cert_id rejected", status(dump(pkg, os.path.join(tmp, "t3.json"))) == "invalid")

    # 7. Untrusted / replaced public key
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    attacker_pem = attacker.public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    attacker_kid = trust_store.key_id_from_public_pem(attacker_pem)
    forged = json.load(open(pathA))
    forged["certificate"]["course_name"] = "PhD Forgery"
    from canonical import field_commitment, signing_payload, make_salt
    forged["salts"]["course_name"] = make_salt()
    forged["commitments"]["course_name"] = field_commitment("course_name", "PhD Forgery", forged["salts"]["course_name"])
    payload = signing_payload(forged["certificate"]["cert_id"], 1, forged["commitments"]).encode()
    forged["signature"] = base64.b64encode(attacker.sign(
        payload, padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())).decode()
    f1 = copy.deepcopy(forged); f1["key_id"] = attacker_kid; f1["public_key"] = attacker_pem
    check("offline: forged credential with attacker's own key -> untrusted_key",
          status(dump(f1, os.path.join(tmp, "f1.json"))) == "untrusted_key")
    f2 = copy.deepcopy(forged); f2["public_key"] = attacker_pem        # claims the REAL key id
    check("offline: attacker key embedded but real key_id claimed -> invalid",
          status(dump(f2, os.path.join(tmp, "f2.json"))) == "invalid")
    f3 = copy.deepcopy(forged); f3.pop("key_id", None)
    check("offline: forged credential without key_id -> invalid",
          status(dump(f3, os.path.join(tmp, "f3.json"))) == "invalid")

    # 6/8. Snapshot freshness and authenticity
    future = trust_store.utcnow() + datetime.timedelta(days=3)
    check("stale snapshot: valid cert is NOT reported valid",
          status(pathA, now=future) == "revocation_unconfirmed")
    check("stale snapshot: revocation is still reported (revoked stays revoked)",
          status(pathB, now=future) == "revoked")

    empty_store = os.path.join(tmp, "store_no_snapshot"); os.makedirs(empty_store)
    shutil.copy(os.path.join(trust_store.VERIFIER_DIR, trust_store.TRUST_FILENAME), empty_store)
    check("missing snapshot: not reported valid", status(pathA, store_dir=empty_store) == "revocation_unconfirmed")

    bad_store = os.path.join(tmp, "store_tampered"); os.makedirs(bad_store)
    shutil.copy(os.path.join(trust_store.VERIFIER_DIR, trust_store.TRUST_FILENAME), bad_store)
    doc = json.load(open(trust_store.local_snapshot_path(1)))
    doc["snapshot"]["revocations"] = []                                  # try to hide B's revocation
    dump(doc, os.path.join(bad_store, "revocations_1.json"))
    check("tampered snapshot (revocation hidden): B is NOT reported valid",
          status(pathB, store_dir=bad_store) == "revocation_unconfirmed")

    fake = {"snapshot": {"version": 1, "institution_id": 1, "key_id": attacker_kid,
                         "issued_at": trust_store.fmt_time(trust_store.utcnow()),
                         "valid_until": trust_store.fmt_time(trust_store.utcnow() + datetime.timedelta(days=9)),
                         "ledger_head": "0" * 64, "ledger_count": 0, "revocations": []}}
    fake["signature"] = base64.b64encode(attacker.sign(
        trust_store.canonical_json(fake["snapshot"]).encode(),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256())).decode()
    dump(fake, os.path.join(bad_store, "revocations_1.json"))
    check("snapshot signed by an untrusted key: B is NOT reported valid",
          status(pathB, store_dir=bad_store) == "revocation_unconfirmed")

    check("institution with no pinned key -> unknown_institution",
          status(pathA, store_dir=os.path.join(tmp, "nowhere")) == "unknown_institution")

    rollback = trust_store.refresh_from_published(published_dir=old_snapshot)
    check("rollback to an older authentic snapshot is refused", rollback[0]["status"] == "rejected"
          and "older" in rollback[0]["message"], rollback[0]["message"])

    # --------------------------------------------------------- data minimization
    print("\n--- Data minimization ---")
    full = json.load(open(pathA)); proof = json.load(open(presA))
    print("      full credential reveals :", sorted(full["certificate"]))
    print("      shareable proof reveals :", sorted(proof["certificate"]))
    hidden = ("grade", "student_id", "student_name")
    leaked = [f for f in hidden if f in proof["certificate"] or f in proof["salts"]]
    check("proof contains no grade / student_id / name (values or salts)", not leaked, str(leaked))
    check("proof reveals only course_name + issue_date (plus core ids)",
          set(proof["certificate"]) == {"cert_id", "institution_id", "course_name", "issue_date"})
    check("proof still verifies (signature intact)", status(presA) == "valid")
    pr = copy.deepcopy(proof); pr["certificate"]["course_name"] = "MBA"
    check("proof: tampered course rejected", status(dump(pr, os.path.join(tmp, "p1.json"))) == "invalid")
    pr = copy.deepcopy(proof); pr["certificate"]["grade"] = "10.00"
    check("proof: adding an undisclosed field without its salt rejected",
          status(dump(pr, os.path.join(tmp, "p2.json"))) == "invalid")
    pr = copy.deepcopy(proof); pr["certificate"]["grade"] = "10.00"; pr["salts"]["grade"] = make_salt()
    check("proof: adding a field with a made-up salt rejected",
          status(dump(pr, os.path.join(tmp, "p3.json"))) == "invalid")
    res = verify_credential(presA)
    check("verifier result exposes only course/date/institution",
          set(res.disclosed) == {"course_name", "issue_date"} and res.institution_name)

    # ------------------------------------------------------------- Flask verifier, DB blocked
    try:
        import io
        import app as flask_app
        client = flask_app.app.test_client()
        for label, p in (("proof", presA), ("full credential", pathA)):
            html = client.post("/verifier", data={"credential": (io.BytesIO(open(p, "rb").read()), "c.json")},
                               content_type="multipart/form-data").get_data(as_text=True)
            check("Flask verifier (%s, DB blocked): shows VALID + course" % label,
                  "VALID" in html and "B.Tech Computer Science" in html)
            body = html[html.index("<main>"):]
            check("Flask verifier (%s): does not display grade, student id or name" % label,
                  "8.70" not in body and "Student" not in body and "student_name" not in body
                  and "Riya" not in body)
    except Blocked as exc:
        check("Flask verifier made no database call", False, str(exc))
    except ImportError as exc:
        print("SKIP  Flask checks (%s)" % exc)
finally:
    unblock_everything()
    shutil.rmtree(tmp, ignore_errors=True)

print("\n%d passed, %d failed" % (sum(results), len(results) - sum(results)))
sys.exit(0 if all(results) else 1)
