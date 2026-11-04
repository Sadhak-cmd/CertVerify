"""
anomaly_detector.py
Train an Isolation Forest on certificate features and flag anomalies.

Usage:
    python anomaly_detector.py \
        --contamination 0.05 \
        --n-estimators  200  \
        --save-model    model.pkl \
        --plot
"""

import argparse
import logging
import pickle
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import LabelEncoder

from db_connect import managed_connection

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data loading
# ---------------------------------------------------------------------------

def load_features() -> pd.DataFrame:
    """
    Pull certificate data from MySQL and engineer features for the model.

    Feature set
    -----------
    - issuer_id           (int)
    - recipient_id        (int)
    - course_enc          (label-encoded course name)
    - grade_enc           (label-encoded grade)
    - issue_year          (int)
    - issue_month         (int)
    - issue_day_of_week   (int)
    - validity_days       (int  — expiry minus issue date)
    - cert_hash_entropy   (float — Shannon entropy of the hex cert_hash)
    - prev_hash_is_null   (bool — 1 for genesis / chain-start cert)
    """
    query = """
        SELECT
            cert_id,
            cert_uuid,
            issuer_id,
            recipient_id,
            course_name,
            grade,
            issue_date,
            expiry_date,
            cert_hash,
            prev_cert_hash,
            chain_hash,
            is_revoked
        FROM certificates
    """
    with managed_connection() as (_, cur):
        cur.execute(query)
        rows = cur.fetchall()

    if not rows:
        raise RuntimeError("No certificates found. Run generate_synthetic_data.py first.")

    df = pd.DataFrame(rows)

    # Date features
    df["issue_date"]  = pd.to_datetime(df["issue_date"])
    df["expiry_date"] = pd.to_datetime(df["expiry_date"])
    df["issue_year"]        = df["issue_date"].dt.year
    df["issue_month"]       = df["issue_date"].dt.month
    df["issue_day_of_week"] = df["issue_date"].dt.dayofweek

    df["validity_days"] = (
        (df["expiry_date"] - df["issue_date"]).dt.days.fillna(-1).astype(int)
    )

    # Encoding
    le_course = LabelEncoder()
    le_grade  = LabelEncoder()
    df["course_enc"] = le_course.fit_transform(df["course_name"].fillna("unknown"))
    df["grade_enc"]  = le_grade.fit_transform(df["grade"].fillna("unknown"))

    # Hash entropy (anomalous hashes may have different entropy profiles)
    df["cert_hash_entropy"] = df["cert_hash"].apply(_hex_entropy)
    df["prev_hash_is_null"] = df["prev_cert_hash"].isna().astype(int)

    logger.info("Loaded %d certificates with %d features.", len(df), 9)
    return df


def _hex_entropy(hex_str: str) -> float:
    """Shannon entropy of a hex string (bits per character)."""
    if not hex_str:
        return 0.0
    counts = np.array([hex_str.count(c) for c in set(hex_str)], dtype=float)
    probs  = counts / counts.sum()
    return float(-np.sum(probs * np.log2(probs + 1e-12)))


# ---------------------------------------------------------------------------
# Feature matrix
# ---------------------------------------------------------------------------

FEATURE_COLS = [
    "issuer_id",
    "recipient_id",
    "course_enc",
    "grade_enc",
    "issue_year",
    "issue_month",
    "issue_day_of_week",
    "validity_days",
    "cert_hash_entropy",
    "prev_hash_is_null",
]


# ---------------------------------------------------------------------------
# Model training + scoring
# ---------------------------------------------------------------------------

def train_isolation_forest(
    df: pd.DataFrame,
    contamination: float = 0.05,
    n_estimators: int = 200,
    random_state: int = 42,
) -> IsolationForest:
    """Fit and return an Isolation Forest on the feature matrix."""
    X = df[FEATURE_COLS].values
    clf = IsolationForest(
        n_estimators=n_estimators,
        contamination=contamination,
        random_state=random_state,
        n_jobs=-1,
    )
    clf.fit(X)
    logger.info(
        "Trained IsolationForest (n_estimators=%d, contamination=%.2f).",
        n_estimators, contamination,
    )
    return clf


def score_and_persist(df: pd.DataFrame, clf: IsolationForest) -> pd.DataFrame:
    """
    Score every certificate and write results to anomaly_scores table.

    Returns
    -------
    pd.DataFrame
        The original df with added columns: if_score, is_anomaly.
    """
    X = df[FEATURE_COLS].values
    # decision_function: negative → anomaly
    df = df.copy()
    df["if_score"]   = clf.decision_function(X)
    df["is_anomaly"] = (clf.predict(X) == -1).astype(int)

    with managed_connection() as (_, cur):
        # Clear previous scores
        cur.execute("DELETE FROM anomaly_scores")
        rows = [
            (int(row.cert_id), float(row.if_score), int(row.is_anomaly))
            for row in df.itertuples(index=False)
        ]
        cur.executemany(
            "INSERT INTO anomaly_scores (cert_id, score, is_anomaly) VALUES (%s, %s, %s)",
            rows,
        )

    n_anomalies = df["is_anomaly"].sum()
    logger.info(
        "Scored %d certs — %d anomalies detected (%.1f%%).",
        len(df), n_anomalies, 100 * n_anomalies / len(df),
    )
    return df


# ---------------------------------------------------------------------------
# Optional plot
# ---------------------------------------------------------------------------

def plot_scores(df: pd.DataFrame) -> None:
    try:
        import matplotlib.pyplot as plt
    except ImportError:
        logger.warning("matplotlib not installed; skipping plot.")
        return

    fig, ax = plt.subplots(figsize=(12, 4))
    colors = df["is_anomaly"].map({0: "#4CAF50", 1: "#F44336"})
    ax.scatter(df.index, df["if_score"], c=colors, alpha=0.6, s=15, edgecolors="none")
    ax.axhline(0, color="gray", linestyle="--", linewidth=0.8, label="Decision boundary")
    ax.set_title("Isolation Forest Anomaly Scores per Certificate", fontsize=14)
    ax.set_xlabel("Certificate index")
    ax.set_ylabel("Decision score (negative = anomaly)")
    ax.legend(handles=[
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="#F44336", markersize=8, label="Anomaly"),
        plt.Line2D([0], [0], marker="o", color="w", markerfacecolor="#4CAF50", markersize=8, label="Normal"),
    ])
    plt.tight_layout()
    plt.savefig("anomaly_scores.png", dpi=150)
    logger.info("Plot saved to anomaly_scores.png")
    plt.show()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def run(
    contamination: float = 0.05,
    n_estimators: int = 200,
    save_model: Optional[str] = None,
    do_plot: bool = False,
) -> pd.DataFrame:
    df  = load_features()
    clf = train_isolation_forest(df, contamination, n_estimators)
    df  = score_and_persist(df, clf)

    if save_model:
        path = Path(save_model)
        with open(path, "wb") as f:
            pickle.dump(clf, f)
        logger.info("Model saved to %s", path)

    if do_plot:
        plot_scores(df)

    # Print top anomalies
    top = df[df["is_anomaly"] == 1].nsmallest(10, "if_score")[
        ["cert_uuid", "if_score", "course_name", "issuer_id"]
    ]
    if not top.empty:
        print("\nTop anomalous certificates:")
        print(top.to_string(index=False))

    return df


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Run Isolation Forest anomaly detection.")
    p.add_argument("--contamination", type=float, default=0.05)
    p.add_argument("--n-estimators",  type=int,   default=200)
    p.add_argument("--save-model",    type=str,   default=None,  help="Path to save .pkl model")
    p.add_argument("--plot",          action="store_true",        help="Show score scatter plot")
    return p.parse_args()


if __name__ == "__main__":
    args = _parse_args()
    run(
        contamination=args.contamination,
        n_estimators=args.n_estimators,
        save_model=args.save_model,
        do_plot=args.plot,
    )
