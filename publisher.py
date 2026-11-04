"""
publisher.py
INSTITUTION side: publishes (1) authenticated public-key information and (2) a signed
revocation snapshot into published/. These are the only things a verifier needs from the
institution, and they are plain files that could be served by any static web host.

Uses the database (it is the institution's own system). The verifier never imports this file.

Usage (from the project folder):
    python publisher.py                    # publish key info + revocation snapshot for every institution that has keys
    python publisher.py --institution 1    # one institution
    python publisher.py --trust --sync     # ALSO simulate the verifier: pin the key and download the list

--trust is the demo stand-in for the out-of-band step in which a verifier checks the printed
fingerprint against another channel (the institution's website, a phone call, a prospectus)
before trusting it. --sync is the stand-in for the verifier downloading the latest list.
"""

import argparse
import base64
import datetime
import json
import os
import re
from typing import Any, Dict, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

import trust_store
from db_connect import get_connection
from key_manager import get_or_create_institution_keys

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLISHED_DIR = trust_store.PUBLISHED_DIR
GENESIS_HASH = "0" * 64
DEFAULT_TTL_HOURS = float(os.environ.get("CERT_SNAPSHOT_TTL_HOURS", "24"))


def _public_pem(private_key) -> str:
    # Derived from the private key itself, never from the database column.
    return private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")


def _institution_name(institution_id: int) -> str:
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM institutions WHERE institution_id = %s;", (institution_id,))
        row = cur.fetchone()
    finally:
        conn.close()
    if row:
        for col in ("institution_name", "name"):
            if row.get(col):
                return str(row[col])
        for col, val in row.items():
            if "name" in col.lower() and val:
                return str(val)
    return "Institution {}".format(institution_id)


def institutions_with_keys() -> list:
    keys_dir = os.path.join(BASE_DIR, "keys")
    ids = []
    if os.path.isdir(keys_dir):
        for name in os.listdir(keys_dir):
            m = re.match(r"^institution_(\d+)_private\.pem$", name)
            if m:
                ids.append(int(m.group(1)))
    return sorted(ids)


def publish_key_info(institution_id: int, out_dir: Optional[str] = None) -> str:
    """Write published/institution_<id>_keyinfo.json (name, public key, key id)."""
    out_dir = out_dir or PUBLISHED_DIR
    private_key, _ = get_or_create_institution_keys(institution_id)
    pem = _public_pem(private_key)
    info = {
        "institution_id": int(institution_id),
        "name": _institution_name(institution_id),
        "key_id": trust_store.key_id_from_public_pem(pem),
        "public_key": pem,
    }
    path = os.path.join(out_dir, "institution_{}_keyinfo.json".format(int(institution_id)))
    trust_store._write_json_atomic(path, info)
    return path


def build_snapshot(institution_id: int, ttl_hours: Optional[float] = None,
                   now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """
    Build the (unsigned) revocation snapshot for one institution from the revocations ledger.

    Privacy: the free-text revocation reason is deliberately NOT published (cert_id + date only).
    Each entry carries its ledger hashes so the institution (or an auditor given the ledger)
    can tie the list back to the hash-chained log.
    """
    now = now or trust_store.utcnow()
    ttl = DEFAULT_TTL_HOURS if ttl_hours is None else ttl_hours
    private_key, _ = get_or_create_institution_keys(institution_id)
    key_id = trust_store.key_id_from_public_pem(_public_pem(private_key))

    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT r.cert_id, r.revoked_at, r.revocation_hash, r.prev_hash "
            "FROM revocations r JOIN certificates c ON c.cert_id = r.cert_id "
            "WHERE c.institution_id = %s ORDER BY r.revocation_id;",
            (institution_id,),
        )
        rows = cur.fetchall()
        cur.execute("SELECT COUNT(*) FROM revocations;")
        count = int(cur.fetchall()[0][0])          # fetchall() fully consumes each result (MySQL connector)
        cur.execute("SELECT revocation_hash FROM revocations ORDER BY revocation_id DESC LIMIT 1;")
        head_rows = cur.fetchall()
        head = head_rows[0][0] if head_rows else GENESIS_HASH
    finally:
        conn.close()

    entries, seen = [], set()
    for cert_id, revoked_at, rev_hash, prev_hash in rows:
        if int(cert_id) in seen:
            continue
        seen.add(int(cert_id))
        entries.append({"cert_id": int(cert_id), "revoked_at": str(revoked_at)[:19],
                        "revocation_hash": rev_hash, "prev_hash": prev_hash})

    return {
        "version": 1,
        "institution_id": int(institution_id),
        "key_id": key_id,
        "issued_at": trust_store.fmt_time(now),
        "valid_until": trust_store.fmt_time(now + datetime.timedelta(hours=ttl)),
        "ledger_head": head,
        "ledger_count": count,
        "revocations": entries,
    }


def publish_revocation_snapshot(institution_id: int, out_dir: Optional[str] = None,
                                ttl_hours: Optional[float] = None,
                                now: Optional[datetime.datetime] = None) -> str:
    """Sign the snapshot with the institution's private key and write published/revocations_<id>.json."""
    out_dir = out_dir or PUBLISHED_DIR
    snapshot = build_snapshot(institution_id, ttl_hours, now)
    private_key, _ = get_or_create_institution_keys(institution_id)
    signature = private_key.sign(
        trust_store.canonical_json(snapshot).encode("utf-8"),
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
        hashes.SHA256(),
    )
    doc = {"snapshot": snapshot, "signature": base64.b64encode(signature).decode("utf-8")}
    path = os.path.join(out_dir, "revocations_{}.json".format(int(institution_id)))
    trust_store._write_json_atomic(path, doc)
    return path


def publish_all(institution_id: int, trust: bool = False, sync: bool = False,
                ttl_hours: Optional[float] = None) -> Dict[str, Any]:
    """Publish key info + a fresh signed snapshot. Optionally act as the verifier (trust / sync)."""
    result = {"keyinfo": publish_key_info(institution_id),
              "snapshot": publish_revocation_snapshot(institution_id, ttl_hours=ttl_hours)}
    if trust:
        result["trusted"] = trust_store.import_key_info(result["keyinfo"])
    if sync:
        result["sync"] = trust_store.refresh_from_published()
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description="Publish key info and a signed revocation snapshot.")
    parser.add_argument("--institution", type=int, help="institution id (default: all that have keys)")
    parser.add_argument("--trust", action="store_true", help="demo: pin the published key in verifier_store/")
    parser.add_argument("--sync", action="store_true", help="demo: download the revocation lists into verifier_store/")
    parser.add_argument("--ttl-hours", type=float, default=None, help="snapshot lifetime (default 24)")
    args = parser.parse_args()

    ids = [args.institution] if args.institution else institutions_with_keys()
    if not ids:
        print("No institution keys found yet. Issue a certificate first (keys are created automatically).")
        return
    for inst in ids:
        res = publish_all(inst, trust=args.trust, sync=args.sync, ttl_hours=args.ttl_hours)
        info = json.load(open(res["keyinfo"], "r", encoding="utf-8"))
        print("Institution {} ({})".format(inst, info["name"]))
        print("  key fingerprint : {}".format(info["key_id"]))
        print("  published       : {}".format(os.path.relpath(res["keyinfo"], BASE_DIR)))
        print("  published       : {}".format(os.path.relpath(res["snapshot"], BASE_DIR)))
        if args.trust:
            print("  verifier trusts this key (pinned in verifier_store/trusted_keys.json)")
    if args.sync:
        for rep in trust_store.refresh_from_published():
            print("  sync {}: {} - {}".format(rep["file"], rep["status"], rep["message"]))


if __name__ == "__main__":
    main()
