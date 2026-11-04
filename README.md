# Certificate Verification System

A tamper-evident, hash-chained certificate issuance and verification platform backed by **MySQL**, with **Isolation Forest** anomaly detection and an optional **Flask REST API**.

---

## Table of Contents

1. [Overview](#overview)
2. [Architecture](#architecture)
3. [File Structure](#file-structure)
4. [Prerequisites](#prerequisites)
5. [Setup](#setup)
6. [Usage](#usage)
   - [Database initialisation](#1-initialise-the-database)
   - [Generate synthetic data](#2-generate-synthetic-data)
   - [Issue a certificate](#3-issue-a-certificate)
   - [Verify a certificate](#4-verify-a-certificate)
   - [Run anomaly detection](#5-run-anomaly-detection)
   - [Start the Flask API](#6-start-the-flask-api)
7. [API Reference](#api-reference)
8. [Hash-Chain Design](#hash-chain-design)
9. [Anomaly Detection](#anomaly-detection)
10. [Environment Variables](#environment-variables)

---

## Overview

Traditional certificate management is prone to forgery and silent data tampering. This system addresses those risks by:

- **Hash-chaining** every certificate to its predecessor (similar to a blockchain), making retroactive edits detectable.
- **Automated anomaly detection** using Isolation Forest to surface statistically unusual issuance patterns.
- **Full audit trail** via a `verification_logs` table that records every verification attempt.

---

## Architecture

```
┌───────────────────────────────────────────────────────┐
│                     Flask REST API                    │
│                        app.py                         │
└──────────────┬──────────────────────┬─────────────────┘
               │                      │
   ┌───────────▼──────────┐  ┌────────▼────────────┐
   │  issue_certificate.py │  │ verify_certificate.py│
   └───────────┬───────────┘  └────────┬────────────┘
               │                       │
   ┌───────────▼───────────────────────▼────────────┐
   │                  db_connect.py                 │
   │          (MySQL connection helper)             │
   └───────────────────────┬────────────────────────┘
                           │
              ┌────────────▼──────────────┐
              │    MySQL: cert_verification│
              │  ┌─────────────────────┐  │
              │  │ issuers             │  │
              │  │ recipients          │  │
              │  │ certificates ←chain │  │
              │  │ verification_logs   │  │
              │  │ anomaly_scores      │  │
              │  └─────────────────────┘  │
              └───────────────────────────┘
                           ▲
            ┌──────────────┘
            │  anomaly_detector.py
            │  (Isolation Forest)
```

---

## File Structure

```
cert-verification-system/
│
├── schema.sql                  # DDL — table creation SQL
├── db_connect.py               # Reusable MySQL connection helper
├── issue_certificate.py        # Issue + hash-chain a certificate
├── verify_certificate.py       # Verify a certificate against the chain
├── generate_synthetic_data.py  # Creates fake issuance data for testing
├── anomaly_detector.py         # Trains + runs Isolation Forest
├── app.py                      # Flask REST API
└── README.md                   # This file
```

---

## Prerequisites

| Dependency       | Version  | Notes                        |
|------------------|----------|------------------------------|
| Python           | ≥ 3.11   |                              |
| MySQL            | ≥ 8.0    | Local or remote instance     |
| mysql-connector-python | any | `pip install mysql-connector-python` |
| Faker            | any      | `pip install faker`          |
| scikit-learn     | ≥ 1.3    | For anomaly detection        |
| pandas           | ≥ 2.0    | For feature engineering      |
| numpy            | ≥ 1.25   |                              |
| Flask            | ≥ 3.0    | Optional API                 |
| flask-cors       | any      | Optional API                 |
| matplotlib       | any      | Optional plots               |

Install all at once:

```bash
pip install mysql-connector-python faker scikit-learn pandas numpy flask flask-cors matplotlib
```

---

## Setup

### 1. Initialise the Database

```bash
mysql -u root -p < schema.sql
```

This creates the `cert_verification` database and all five tables.

### 2. Configure the connection

Set environment variables (or edit `db_connect.py`):

```bash
export DB_HOST=localhost
export DB_PORT=3306
export DB_USER=root
export DB_PASSWORD=your_password
export DB_NAME=cert_verification
```

---

## Usage

### 1. Initialise the Database

```bash
mysql -u root -p < schema.sql
```

### 2. Generate Synthetic Data

```bash
python generate_synthetic_data.py \
    --issuers    10  \
    --recipients 200 \
    --certs      500 \
    --anomalies  0.05
```

This seeds the DB with 10 issuers, 200 recipients, and 500 certificates, of which ~5% have deliberately tampered hashes.

### 3. Issue a Certificate

```bash
python issue_certificate.py \
    --recipient-email student@example.com \
    --issuer-email    uni@example.com \
    --course          "Machine Learning Fundamentals" \
    --grade           "A" \
    --issue-date      2026-09-01 \
    --expiry-date     2029-09-01
```

Output:
```
Certificate issued successfully. UUID: 550e8400-e29b-41d4-a716-446655440000
```

### 4. Verify a Certificate

```bash
python verify_certificate.py --uuid 550e8400-e29b-41d4-a716-446655440000
```

Output:
```
Status  : VALID
Message : Certificate is authentic and the hash chain is intact.

Details:
  cert_uuid            : 550e8400-e29b-41d4-a716-446655440000
  recipient_name       : Jane Doe
  course_name          : Machine Learning Fundamentals
  grade                : A
  issue_date           : 2026-09-01
  ...
```

### 5. Run Anomaly Detection

```bash
python anomaly_detector.py \
    --contamination 0.05 \
    --n-estimators  200  \
    --save-model    model.pkl \
    --plot
```

Results are written to the `anomaly_scores` table and printed to stdout.

### 6. Start the Flask API

```bash
python app.py
```

The server starts at `http://localhost:5000`.

---

## API Reference

| Method | Endpoint                              | Description                      |
|--------|---------------------------------------|----------------------------------|
| GET    | `/api/health`                         | Health check                     |
| POST   | `/api/certificates/issue`             | Issue a new certificate          |
| GET    | `/api/certificates/<uuid>/verify`     | Verify a certificate             |
| GET    | `/api/certificates/<uuid>`            | Fetch certificate details        |
| POST   | `/api/anomaly/run`                    | Run Isolation Forest detection   |
| GET    | `/api/anomaly/scores`                 | List anomaly scores              |

### POST `/api/certificates/issue`

```json
{
  "recipient_email": "student@example.com",
  "issuer_email":    "uni@example.com",
  "course_name":     "Machine Learning Fundamentals",
  "issue_date":      "2026-09-01",
  "expiry_date":     "2029-09-01",
  "grade":           "A"
}
```

### GET `/api/certificates/<uuid>/verify`

```json
{
  "ok": true,
  "data": {
    "status":  "VALID",
    "message": "Certificate is authentic and the hash chain is intact.",
    "details": { ... }
  }
}
```

---

## Hash-Chain Design

Each certificate stores three hash values:

| Field           | Formula                                        |
|-----------------|------------------------------------------------|
| `cert_hash`     | `SHA-256(canonical JSON of cert payload)`      |
| `prev_cert_hash`| `chain_hash` of the immediately preceding cert |
| `chain_hash`    | `SHA-256(cert_hash + prev_cert_hash)`          |

Verification recomputes both `cert_hash` and `chain_hash` from the raw data and compares them to the stored values. Any discrepancy reveals tampering.

The first certificate in the chain uses the sentinel string `"GENESIS"` as `prev_cert_hash`.

---

## Anomaly Detection

The Isolation Forest is trained on the following features extracted from every certificate:

| Feature              | Description                                  |
|----------------------|----------------------------------------------|
| `issuer_id`          | Integer ID of the issuing organisation       |
| `recipient_id`       | Integer ID of the recipient                  |
| `course_enc`         | Label-encoded course name                    |
| `grade_enc`          | Label-encoded grade                          |
| `issue_year`         | Calendar year of issuance                    |
| `issue_month`        | Month of issuance                            |
| `issue_day_of_week`  | Day of week (0 = Monday)                     |
| `validity_days`      | `expiry_date - issue_date` in days           |
| `cert_hash_entropy`  | Shannon entropy of the hex cert_hash string  |
| `prev_hash_is_null`  | 1 if this is the first cert in the chain     |

Certificates with a negative `decision_function` score are labelled as anomalies and written to the `anomaly_scores` table.

---

## Environment Variables

| Variable      | Default       | Description               |
|---------------|---------------|---------------------------|
| `DB_HOST`     | `localhost`   | MySQL host                |
| `DB_PORT`     | `3306`        | MySQL port                |
| `DB_USER`     | `root`        | MySQL username            |
| `DB_PASSWORD` | *(empty)*     | MySQL password            |
| `DB_NAME`     | `cert_verification` | Database name        |

---

## License

MIT — see `LICENSE` for details.
