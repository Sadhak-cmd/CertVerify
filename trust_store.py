"""
trust_store.py
Verifier-side trust anchors and revocation snapshots.

IMPORTANT: this module (and verify_credential.py, which uses it) must NEVER touch the
database. It only reads local files under verifier_store/.

What lives here
---------------
verifier_store/trusted_keys.json
    The verifier's own list of trusted institution keys, pinned by key id (the SHA-256
    fingerprint of the public key). A key becomes trusted ONLY through import_key_info(),
    which is an explicit act (see publisher.py --trust). A public key that merely appears
    inside a credential is never trusted.

verifier_store/revocations_<institution_id>.json
    The verifier's local copy of the institution's signed revocation list. It is
    authenticated with a pinned key before its contents are believed.

Python 3.8 compatible.
"""

import base64
import binascii
import datetime
import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple, Union

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLISHED_DIR = os.path.join(BASE_DIR, "published")        # what an institution publishes
VERIFIER_DIR = os.path.join(BASE_DIR, "verifier_store")    # what a verifier keeps locally
TRUST_FILENAME = "trusted_keys.json"

TIME_FMT = "%Y-%m-%dT%H:%M:%SZ"
CLOCK_SKEW = datetime.timedelta(minutes=10)


# ---------------------------------------------------------------- time helpers

def utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def fmt_time(dt: datetime.datetime) -> str:
    return dt.strftime(TIME_FMT)


def parse_time(value: str) -> datetime.datetime:
    return datetime.datetime.strptime(value, TIME_FMT)


# --------------------------------------------------------------- crypto helpers

def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def key_id_from_public_pem(public_pem: Union[str, bytes]) -> str:
    """Key id = SHA-256 of the DER SubjectPublicKeyInfo encoding of the public key."""
    if isinstance(public_pem, str):
        public_pem = public_pem.encode("utf-8")
    key = serialization.load_pem_public_key(public_pem)
    der = key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return hashlib.sha256(der).hexdigest()


def verify_signature(public_pem: Union[str, bytes], signature_b64: str, message: bytes) -> bool:
    """RSA-PSS / SHA-256 verification. Returns False on any failure instead of raising."""
    try:
        if isinstance(public_pem, str):
            public_pem = public_pem.encode("utf-8")
        public_key = serialization.load_pem_public_key(public_pem)
        public_key.verify(
            base64.b64decode(signature_b64),
            message,
            padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
            hashes.SHA256(),
        )
        return True
    except (InvalidSignature, ValueError, TypeError, binascii.Error):
        return False
    except Exception:
        return False


# ------------------------------------------------------------------ trust store

def _dir(store_dir: Optional[str]) -> str:
    return store_dir or VERIFIER_DIR


def _write_json_atomic(path: str, obj: Any) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, indent=2)
    os.replace(tmp, path)


def load_trust_store(store_dir: Optional[str] = None) -> Dict[str, Any]:
    """Return {"keys": {key_id: {"institution_id", "name", "public_key"}}}. Fails closed (empty)."""
    path = os.path.join(_dir(store_dir), TRUST_FILENAME)
    if not os.path.exists(path):
        return {"keys": {}}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception:
        return {"keys": {}}
    if not isinstance(data, dict) or not isinstance(data.get("keys"), dict):
        return {"keys": {}}
    return data


def trusted_keys_for(institution_id: Any, key_id: Optional[str] = None,
                     store_dir: Optional[str] = None) -> List[Tuple[str, Dict[str, Any]]]:
    """
    Trusted (key_id, entry) pairs for an institution, optionally narrowed to one key id.
    An entry whose stored public key does not hash to its own key id is ignored, so editing a
    key inside the trust file without updating its id cannot smuggle a different key in.
    """
    out = []
    try:
        wanted = int(institution_id)
    except (TypeError, ValueError):
        return out
    for kid, entry in load_trust_store(store_dir)["keys"].items():
        try:
            if int(entry.get("institution_id")) != wanted:
                continue
            if key_id is not None and kid != key_id:
                continue
            if key_id_from_public_pem(entry["public_key"]) != kid:
                continue
        except Exception:
            continue
        out.append((kid, entry))
    return out


def import_key_info(keyinfo: Union[str, Dict[str, Any]], expected_key_id: Optional[str] = None,
                    store_dir: Optional[str] = None) -> Dict[str, Any]:
    """
    Explicitly trust an institution's key. `keyinfo` is a dict or a path to a published
    institution_<id>_keyinfo.json. The key id is recomputed from the public key; if
    `expected_key_id` is given (a fingerprint obtained out-of-band) it must match.
    """
    if isinstance(keyinfo, str):
        with open(keyinfo, "r", encoding="utf-8") as fh:
            keyinfo = json.load(fh)
    institution_id = int(keyinfo["institution_id"])
    public_pem = keyinfo["public_key"]
    computed = key_id_from_public_pem(public_pem)
    if keyinfo.get("key_id") and keyinfo["key_id"] != computed:
        raise ValueError("key info is inconsistent: key_id does not match the public key")
    if expected_key_id is not None and expected_key_id != computed:
        raise ValueError("fingerprint mismatch: expected {} but the key is {}".format(expected_key_id, computed))

    store = load_trust_store(store_dir)
    store["keys"][computed] = {
        "institution_id": institution_id,
        "name": str(keyinfo.get("name") or "Institution {}".format(institution_id)),
        "public_key": public_pem,
    }
    _write_json_atomic(os.path.join(_dir(store_dir), TRUST_FILENAME), store)
    return {"institution_id": institution_id, "name": store["keys"][computed]["name"], "key_id": computed}


def institution_name(institution_id: Any, store_dir: Optional[str] = None) -> Optional[str]:
    keys = trusted_keys_for(institution_id, None, store_dir)
    return keys[0][1].get("name") if keys else None


# ------------------------------------------------------- revocation snapshots

def _empty_status(exists: bool, error: Optional[str]) -> Dict[str, Any]:
    return {"exists": exists, "authentic": False, "fresh": None, "issued_at": None,
            "valid_until": None, "revoked": {}, "error": error}


def check_snapshot_doc(doc: Any, institution_id: Any, store_dir: Optional[str] = None,
                       now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    """
    Authenticate a signed revocation snapshot against the PINNED keys and judge freshness.
    authentic -> signature verified with a trusted key of this institution.
    fresh     -> authentic and not past its valid_until time.
    Nothing here queries a database.
    """
    now = now or utcnow()
    result = _empty_status(True, None)
    try:
        snap = doc["snapshot"]
        signature = doc["signature"]
        if int(snap["institution_id"]) != int(institution_id):
            raise ValueError("snapshot belongs to a different institution")
        keys = trusted_keys_for(institution_id, snap["key_id"], store_dir)
        if not keys:
            raise ValueError("snapshot is signed by a key this verifier does not trust")
        if not verify_signature(keys[0][1]["public_key"], signature, canonical_json(snap).encode("utf-8")):
            raise ValueError("snapshot signature does not verify (file altered or forged)")
        issued = parse_time(snap["issued_at"])
        valid_until = parse_time(snap["valid_until"])
        if issued > now + CLOCK_SKEW:
            raise ValueError("snapshot claims to be issued in the future")
        revoked = {}
        for entry in snap["revocations"]:
            revoked.setdefault(int(entry["cert_id"]), {"revoked_at": entry.get("revoked_at")})
    except Exception as exc:
        result["error"] = "{}: {}".format(type(exc).__name__, exc)
        return result

    result.update(authentic=True, fresh=(now <= valid_until), issued_at=snap["issued_at"],
                  valid_until=snap["valid_until"], revoked=revoked)
    return result


def local_snapshot_path(institution_id: Any, store_dir: Optional[str] = None) -> str:
    return os.path.join(_dir(store_dir), "revocations_{}.json".format(int(institution_id)))


def load_local_snapshot(institution_id: Any, store_dir: Optional[str] = None,
                        now: Optional[datetime.datetime] = None) -> Dict[str, Any]:
    path = local_snapshot_path(institution_id, store_dir)
    if not os.path.exists(path):
        return _empty_status(False, "no local revocation list has been downloaded")
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except Exception as exc:
        return _empty_status(True, "revocation list file is unreadable ({})".format(type(exc).__name__))
    return check_snapshot_doc(doc, institution_id, store_dir, now)


def refresh_from_published(published_dir: Optional[str] = None, store_dir: Optional[str] = None,
                           now: Optional[datetime.datetime] = None) -> List[Dict[str, Any]]:
    """
    'Download' the latest revocation lists from the institution's publication point into the
    verifier's local store. (On one machine this copies published/ -> verifier_store/; in a
    real deployment it would be an HTTP GET of the same files.)

    A list is only accepted if it is authentic under a pinned key, and never replaces a newer
    authentic local list with an older one (rollback protection at refresh time).
    """
    published_dir = published_dir or PUBLISHED_DIR
    reports = []
    if not os.path.isdir(published_dir):
        return [{"file": None, "status": "rejected", "message": "nothing has been published yet"}]
    for name in sorted(os.listdir(published_dir)):
        match = re.match(r"^revocations_(\d+)\.json$", name)
        if not match:
            continue
        inst = int(match.group(1))
        src = os.path.join(published_dir, name)
        try:
            with open(src, "r", encoding="utf-8") as fh:
                doc = json.load(fh)
        except Exception:
            reports.append({"file": name, "status": "rejected", "message": "unreadable file"})
            continue
        incoming = check_snapshot_doc(doc, inst, store_dir, now)
        if not incoming["authentic"]:
            reports.append({"file": name, "status": "rejected",
                            "message": "not authentic: {}".format(incoming["error"])})
            continue
        local = load_local_snapshot(inst, store_dir, now)
        if local["authentic"] and parse_time(local["issued_at"]) > parse_time(incoming["issued_at"]):
            reports.append({"file": name, "status": "rejected",
                            "message": "older than the list already held (rollback refused)"})
            continue
        _write_json_atomic(local_snapshot_path(inst, store_dir), doc)
        reports.append({"file": name, "status": "updated",
                        "message": "issued {}, valid until {}, {} revoked".format(
                            incoming["issued_at"], incoming["valid_until"], len(incoming["revoked"]))})
    if not reports:
        reports.append({"file": None, "status": "rejected", "message": "no revocation lists found to download"})
    return reports


def trust_summary(store_dir: Optional[str] = None,
                  now: Optional[datetime.datetime] = None) -> List[Dict[str, Any]]:
    """One row per trusted institution, for display: name, key id, and local list status."""
    rows, seen = [], set()
    for kid, entry in load_trust_store(store_dir)["keys"].items():
        try:
            inst = int(entry["institution_id"])
        except Exception:
            continue
        if kid in seen:
            continue
        seen.add(kid)
        rows.append({"institution_id": inst, "name": entry.get("name"), "key_id": kid,
                     "snapshot": load_local_snapshot(inst, store_dir, now)})
    rows.sort(key=lambda r: r["institution_id"])
    return rows
