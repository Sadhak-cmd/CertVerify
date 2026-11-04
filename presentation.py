"""
presentation.py
HOLDER side: derive a minimal "proof" from a full credential, revealing only chosen fields.

The proof keeps the institution's original signature and all commitments, but drops the
plaintext value and salt of every hidden field. A verifier can still check the signature;
it just cannot learn the hidden values (grade, student_id, name) - the 128-bit salts stop it
guessing them. No database, no new cryptography beyond SHA-256.
"""

import json
import os
from typing import Iterable, Optional

from canonical import CORE_FIELDS

DEFAULT_REVEAL = ("course_name", "issue_date")


def create_presentation(credential_json_path: str, reveal: Iterable[str] = DEFAULT_REVEAL,
                        out_path: Optional[str] = None) -> str:
    """Write presentation_<cert_id>.json next to the credential and return its path."""
    with open(credential_json_path, "r", encoding="utf-8") as fh:
        pkg = json.load(fh)
    if pkg.get("version") != 2 or "commitments" not in pkg:
        raise ValueError("Only version 2 credentials support selective disclosure. Re-issue this certificate.")

    cert, salts = pkg["certificate"], pkg["salts"]
    shown = {k: cert[k] for k in CORE_FIELDS}
    shown_salts = {}
    for field in reveal:
        if field in CORE_FIELDS:
            continue
        if field not in cert or field not in salts:
            raise ValueError("Field '{}' is not available in this credential.".format(field))
        shown[field] = cert[field]
        shown_salts[field] = salts[field]

    proof = {
        "version": 2,
        "certificate": shown,
        "salts": shown_salts,
        "commitments": pkg["commitments"],
        "signature": pkg["signature"],
        "institution_id": pkg["institution_id"],
        "key_id": pkg.get("key_id"),
    }
    if out_path is None:
        out_path = os.path.join(os.path.dirname(os.path.abspath(credential_json_path)),
                                "presentation_{}.json".format(cert["cert_id"]))
    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(proof, fh, indent=2)
    return out_path


if __name__ == "__main__":
    import sys
    print(create_presentation(sys.argv[1]))
