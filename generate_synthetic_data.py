"""
generate_synthetic_data.py
Populate the database with realistic fake issuers, recipients,
and certificates for development and testing.

Usage:
    python generate_synthetic_data.py \
        --issuers    10 \
        --recipients 200 \
        --certs      500 \
        --anomalies  0.05        # fraction of certs to flag as suspicious
"""

import argparse
import hashlib
import json
import logging
import random
import uuid
from datetime import date, timedelta
from typing import Optional

from faker import Faker
from db_connect import managed_connection

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)
fake = Faker()

COURSES = [
    "Data Science Fundamentals",
    "Machine Learning A-Z",
    "Full-Stack Web Development",
    "Cloud Architecture on AWS",
    "Cybersecurity Essentials",
    "Python for Data Analysis",
    "Deep Learning with PyTorch",
    "DevOps & CI/CD Pipelines",
    "Blockchain Development",
    "Natural Language Processing",
    "Computer Vision",
    "MLOps in Production",
]

GRADES = ["A+", "A", "A-", "B+", "B", "B-", "C+", "C", "Pass"]


# ---------------------------------------------------------------------------
# Hashing helpers (mirrors issue_certificate.py)
# ---------------------------------------------------------------------------

def sha256(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def build_payload(cert_uuid, recipient_id, issuer_id,
                  course_name, issue_date, expiry_date, grade) -> str:
    payload = {
        "cert_uuid":    cert_uuid,
        "recipient_id": recipient_id,
        "issuer_id":    issuer_id,
        "course_name":  course_name,
        "issue_date":   issue_date,
        "expiry_date":  expiry_date or "",
        "grade":        grade or "",
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"))


def compute_chain_hash(cert_hash: str, prev: Optional[str]) -> str:
    return sha256(cert_hash + (prev or "GENESIS"))


# ---------------------------------------------------------------------------
# Seeding helpers
# ---------------------------------------------------------------------------

def seed_issuers(cur, n: int) -> list[int]:
    """Insert n fake issuers and return their IDs."""
    issuer_ids = []
    for _ in range(n):
        cur.execute(
            """
            INSERT IGNORE INTO issuers (name, email)
            VALUES (%s, %s)
            """,
            (fake.company(), fake.unique.company_email()),
        )
        if cur.lastrowid:
            issuer_ids.append(cur.lastrowid)
    logger.info("Seeded %d issuers.", len(issuer_ids))
    return issuer_ids


def seed_recipients(cur, n: int) -> list[int]:
    """Insert n fake recipients and return their IDs."""
    recipient_ids = []
    for _ in range(n):
        cur.execute(
            """
            INSERT IGNORE INTO recipients (full_name, email, date_of_birth)
            VALUES (%s, %s, %s)
            """,
            (
                fake.name(),
                fake.unique.email(),
                fake.date_of_birth(minimum_age=18, maximum_age=45).isoformat(),
            ),
        )
        if cur.lastrowid:
            recipient_ids.append(cur.lastrowid)
    logger.info("Seeded %d recipients.", len(recipient_ids))
    return recipient_ids


def seed_certificates(
    cur,
    n: int,
    issuer_ids: list[int],
    recipient_ids: list[int],
    anomaly_fraction: float = 0.05,
) -> None:
    """
    Insert n certificates with a valid hash chain.
    anomaly_fraction of certs will have intentionally corrupted hashes
    to simulate tampered / anomalous records.
    """
    prev_chain_hash: Optional[str] = None

    # Fetch the current chain tip (in case table already has data)
    cur.execute("SELECT chain_hash FROM certificates ORDER BY cert_id DESC LIMIT 1")
    tip = cur.fetchone()
    if tip:
        prev_chain_hash = tip["chain_hash"]

    inserted = 0
    for i in range(n):
        cert_uuid    = str(uuid.uuid4())
        recipient_id = random.choice(recipient_ids)
        issuer_id    = random.choice(issuer_ids)
        course_name  = random.choice(COURSES)
        grade        = random.choice(GRADES)

        start = date(2020, 1, 1)
        issue_date  = start + timedelta(days=random.randint(0, 2000))
        expiry_date = issue_date + timedelta(days=random.randint(365, 1095))

        payload    = build_payload(
            cert_uuid, recipient_id, issuer_id,
            course_name, issue_date.isoformat(),
            expiry_date.isoformat(), grade,
        )
        cert_hash  = sha256(payload)
        chain_hash = compute_chain_hash(cert_hash, prev_chain_hash)

        # Simulate anomaly: corrupt the cert_hash
        is_anomaly = random.random() < anomaly_fraction
        stored_cert_hash = (
            sha256(cert_hash + "TAMPERED") if is_anomaly else cert_hash
        )

        cur.execute(
            """
            INSERT INTO certificates
                (cert_uuid, recipient_id, issuer_id, course_name,
                 issue_date, expiry_date, grade,
                 cert_hash, prev_cert_hash, chain_hash)
            VALUES (%s,%s,%s,%s, %s,%s,%s, %s,%s,%s)
            """,
            (
                cert_uuid, recipient_id, issuer_id, course_name,
                issue_date.isoformat(), expiry_date.isoformat(), grade,
                stored_cert_hash, prev_chain_hash, chain_hash,
            ),
        )

        prev_chain_hash = chain_hash
        inserted += 1

        if (i + 1) % 50 == 0:
            logger.info("  Inserted %d / %d certificates…", i + 1, n)

    logger.info("Seeded %d certificates (anomaly_fraction=%.0f%%).",
                inserted, anomaly_fraction * 100)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def generate(
    n_issuers: int = 5,
    n_recipients: int = 100,
    n_certs: int = 300,
    anomaly_fraction: float = 0.05,
) -> None:
    with managed_connection() as (conn, cur):
        issuer_ids    = seed_issuers(cur, n_issuers)
        recipient_ids = seed_recipients(cur, n_recipients)
        seed_certificates(cur, n_certs, issuer_ids, recipient_ids, anomaly_fraction)

    logger.info("Synthetic data generation complete.")


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Seed the DB with synthetic certificate data.")
    p.add_argument("--issuers",    type=int,   default=5,    help="Number of issuers")
    p.add_argument("--recipients", type=int,   default=100,  help="Number of recipients")
    p.add_argument("--certs",      type=int,   default=300,  help="Number of certificates")
    p.add_argument("--anomalies",  type=float, default=0.05, help="Fraction of anomalous certs")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    generate(
        n_issuers=args.issuers,
        n_recipients=args.recipients,
        n_certs=args.certs,
        anomaly_fraction=args.anomalies,
    )
