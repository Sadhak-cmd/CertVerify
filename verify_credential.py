"""
verify_credential.py
Verifies a portable digital credential WITHOUT any database or network access.

Everything it needs is local:
  * the verifier's pinned trust store      (verifier_store/trusted_keys.json)
  * the institution's signed revocation list (verifier_store/revocations_<id>.json)
See trust_store.py. This module must never import db_connect.

Return values (strings, with extra attributes on the returned object):
  'valid'                  signature genuine, key trusted, and NOT on a fresh, authentic revocation list
  'revoked'                signature genuine and the certificate IS on an authentic revocation list
  'revocation_unconfirmed' signature genuine, but revocation status cannot be confirmed
                           (no list, list not authentic, or list expired). NOT a pass.
  'invalid'                tampered, forged, malformed
  'untrusted_key'          the credential names a key this verifier has not pinned for that institution
  'unknown_institution'    the verifier trusts no key at all for that institution
"""

import os
import json
from typing import Any, Dict, Optional
from canonical import CORE_FIELDS, canonical_cert_data, field_commitment, signing_payload
import trust_store

# Fields shown to a verifier. Everything else (grade, student_id, student_name...) is never displayed.
DISPLAY_FIELDS = ("course_name", "issue_date")


class VerificationResult(str):
    """
    String subclass for verification results. Evaluates as a string ('revoked' == result)
    and carries metadata: reason, revoked_at, detail, institution_name, cert_id, disclosed,
    extra_fields, snapshot (revocation-list status), version.
    """
    def __new__(cls, status: str, reason: str = None, revoked_at: Any = None, **meta):
        instance = super().__new__(cls, status)
        instance.reason = reason
        instance.revoked_at = revoked_at
        instance.detail = None
        instance.institution_name = None
        instance.cert_id = None
        instance.disclosed = {}
        instance.extra_fields = []
        instance.snapshot = None
        instance.version = None
        for key, value in meta.items():
            setattr(instance, key, value)
        return instance


def verify_credential(credential_json_path: str, store_dir: Optional[str] = None,
                      now=None) -> str:
    """
    Verify the signature and integrity of a JSON credential (full credential or proof).

    Parameters
    ----------
    credential_json_path : str
        File path to the credential JSON file.
    store_dir : str, optional
        Verifier store folder (default verifier_store/). Mainly for tests.
    now : datetime, optional
        Override the clock (UTC, naive). Mainly for tests of snapshot freshness.
    """
    if not os.path.exists(credential_json_path):
        # Fallback check inside credentials/ directory if relative filename was provided
        alt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "credentials", credential_json_path)
        if os.path.exists(alt_path):
            credential_json_path = alt_path
        else:
            raise FileNotFoundError(f"Credential file not found: {credential_json_path}")

    try:
        with open(credential_json_path, "r", encoding="utf-8") as f:
            package = json.load(f)
    except Exception:
        return VerificationResult("invalid", detail="The file is not valid JSON.")

    if not isinstance(package, dict):
        return VerificationResult("invalid", detail="Not a credential file.")

    cert_data = package.get("certificate")
    signature_b64 = package.get("signature")
    institution_id = package.get("institution_id")
    if not isinstance(cert_data, dict) or not signature_b64 or institution_id is None:
        return VerificationResult("invalid", detail="Missing certificate, signature or institution.")

    version = package.get("version", 1)
    try:
        cert_id = int(cert_data.get("cert_id"))
        institution_id = int(institution_id)
        if cert_data.get("institution_id") is not None and int(cert_data["institution_id"]) != institution_id:
            return VerificationResult("invalid", cert_id=cert_id, version=version,
                                      detail="Institution fields disagree.")
    except (TypeError, ValueError):
        return VerificationResult("invalid", detail="Malformed certificate or institution id.")

    base = dict(cert_id=cert_id, version=version)

    # ---- 1. Establish trust in the institution's key (local trust store, no DB) -------------
    claimed_key_id = package.get("key_id")
    institution_keys = trust_store.trusted_keys_for(institution_id, None, store_dir)
    if not institution_keys:
        return VerificationResult(
            "unknown_institution", **base,
            detail="This verifier does not trust any key for institution {}.".format(institution_id))
    candidates = [k for k in institution_keys if claimed_key_id in (None, k[0])]
    if not candidates:
        return VerificationResult(
            "untrusted_key", **base,
            detail="The credential names a signing key that is not the one pinned for this institution.")

    # ---- 2. Verify the RSA signature locally ------------------------------------------------
    if version == 2:
        commitments = package.get("commitments")
        if not isinstance(commitments, dict) or not commitments:
            return VerificationResult("invalid", **base, detail="Missing commitments.")
        try:
            message = signing_payload(cert_id, institution_id, commitments).encode("utf-8")
        except Exception:
            return VerificationResult("invalid", **base, detail="Malformed commitments.")
    else:
        message = canonical_cert_data(cert_data).encode("utf-8")

    signer = None
    for kid, entry in candidates:
        if trust_store.verify_signature(entry["public_key"], signature_b64, message):
            signer = entry
            break
    if signer is None:
        return VerificationResult(
            "invalid", **base,
            detail="The signature does not match. This credential was tampered with or forged.")
    base["institution_name"] = signer.get("name")

    # ---- 3. (v2) every revealed field must match its signed commitment ----------------------
    disclosed = {}
    extra = []
    if version == 2:
        salts = package.get("salts") or {}
        for field, value in cert_data.items():
            if field in CORE_FIELDS:
                continue
            salt, committed = salts.get(field), commitments.get(field)
            if not salt or committed is None or field_commitment(field, value, salt) != committed:
                return VerificationResult(
                    "invalid", **base,
                    detail="The revealed value of '{}' does not match what the institution signed.".format(field))
            if field in DISPLAY_FIELDS:
                disclosed[field] = value
            else:
                extra.append(field)
    else:
        for field, value in cert_data.items():
            if field in CORE_FIELDS:
                continue
            if field in DISPLAY_FIELDS:
                disclosed[field] = value
            else:
                extra.append(field)
    base["disclosed"], base["extra_fields"] = disclosed, extra

    # ---- 4. Revocation: local, authenticated snapshot only ----------------------------------
    snap = trust_store.load_local_snapshot(institution_id, store_dir, now)
    base["snapshot"] = snap

    if snap["authentic"] and cert_id in snap["revoked"]:
        # Once revoked, always revoked: a stale list can still prove a revocation.
        revoked_at = snap["revoked"][cert_id].get("revoked_at")
        print(f"REVOKED on {revoked_at}.")
        return VerificationResult(
            "revoked", reason=None, revoked_at=str(revoked_at), **base,
            detail="The signature is genuine, but the institution has revoked this certificate.")

    if snap["authentic"] and snap["fresh"]:
        print("VALID. Signature verified, not on the authenticated revocation list.")
        return VerificationResult(
            "valid", **base,
            detail="Signature verified. Not on the institution's revocation list issued {} (valid until {}). "
                   "Revocation status is as of that time.".format(snap["issued_at"], snap["valid_until"]))

    if snap["authentic"]:
        why = "the revocation list expired on {}".format(snap["valid_until"])
    elif not snap["exists"]:
        why = "no revocation list has been downloaded"
    else:
        why = "the local revocation list failed authentication ({})".format(snap["error"])
    print(f"UNCONFIRMED. Signature verified, but {why}.")
    return VerificationResult(
        "revocation_unconfirmed", **base,
        detail="The signature is genuine, but revocation status cannot be confirmed: {}. "
               "Download the latest revocation list and verify again.".format(why))


if __name__ == "__main__":
    example_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "credentials", "credential_7.json")
    if os.path.exists(example_path):
        result = verify_credential(example_path)
        print(f"Verification result for credential_7.json: {result}")
    else:
        print("No credential_7.json found to verify yet.")
