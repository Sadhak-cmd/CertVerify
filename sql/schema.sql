-- =============================================================
-- Certificate Verification System — Database Schema
-- =============================================================

CREATE DATABASE IF NOT EXISTS cert_verification
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE cert_verification;

-- -------------------------------------------------------------
-- Table: issuers
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS issuers (
    issuer_id       INT             AUTO_INCREMENT PRIMARY KEY,
    name            VARCHAR(255)    NOT NULL,
    email           VARCHAR(255)    NOT NULL UNIQUE,
    public_key      TEXT,
    created_at      DATETIME        DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- -------------------------------------------------------------
-- Table: recipients
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS recipients (
    recipient_id    INT             AUTO_INCREMENT PRIMARY KEY,
    full_name       VARCHAR(255)    NOT NULL,
    email           VARCHAR(255)    NOT NULL UNIQUE,
    date_of_birth   DATE,
    created_at      DATETIME        DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB;

-- -------------------------------------------------------------
-- Table: certificates
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS certificates (
    cert_id             INT             AUTO_INCREMENT PRIMARY KEY,
    cert_uuid           CHAR(36)        NOT NULL UNIQUE,
    recipient_id        INT             NOT NULL,
    issuer_id           INT             NOT NULL,
    course_name         VARCHAR(255)    NOT NULL,
    issue_date          DATE            NOT NULL,
    expiry_date         DATE,
    grade               VARCHAR(50),
    cert_hash           CHAR(64)        NOT NULL,
    prev_cert_hash      CHAR(64),
    chain_hash          CHAR(64)        NOT NULL,
    is_revoked          TINYINT(1)      DEFAULT 0,
    revocation_reason   TEXT,
    revoked_at          DATETIME,
    metadata            JSON,
    created_at          DATETIME        DEFAULT CURRENT_TIMESTAMP,
    updated_at          DATETIME        DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    FOREIGN KEY (recipient_id) REFERENCES recipients(recipient_id) ON DELETE RESTRICT,
    FOREIGN KEY (issuer_id)    REFERENCES issuers(issuer_id)       ON DELETE RESTRICT,

    INDEX idx_cert_uuid     (cert_uuid),
    INDEX idx_recipient     (recipient_id),
    INDEX idx_issuer        (issuer_id),
    INDEX idx_issue_date    (issue_date),
    INDEX idx_chain_hash    (chain_hash)
) ENGINE=InnoDB;

-- -------------------------------------------------------------
-- Table: verification_logs
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS verification_logs (
    log_id          INT             AUTO_INCREMENT PRIMARY KEY,
    cert_uuid       CHAR(36)        NOT NULL,
    verified_at     DATETIME        DEFAULT CURRENT_TIMESTAMP,
    result          ENUM('VALID', 'INVALID', 'REVOKED', 'NOT_FOUND') NOT NULL,
    ip_address      VARCHAR(45),
    user_agent      TEXT,
    notes           TEXT,

    INDEX idx_log_cert_uuid (cert_uuid),
    INDEX idx_verified_at   (verified_at)
) ENGINE=InnoDB;

-- -------------------------------------------------------------
-- Table: anomaly_scores
-- -------------------------------------------------------------
CREATE TABLE IF NOT EXISTS anomaly_scores (
    score_id        INT             AUTO_INCREMENT PRIMARY KEY,
    cert_id         INT             NOT NULL,
    score           FLOAT           NOT NULL,
    is_anomaly      TINYINT(1)      DEFAULT 0,
    scored_at       DATETIME        DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (cert_id) REFERENCES certificates(cert_id) ON DELETE CASCADE,
    INDEX idx_score_cert    (cert_id),
    INDEX idx_is_anomaly    (is_anomaly)
) ENGINE=InnoDB;
