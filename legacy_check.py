"""
legacy_check.py
OCR-based verification of legacy (pre-digital) paper certificates against
the institution's digitized historical records stored in the legacy_records table.

Pipeline:
  1. Preprocess image with OpenCV for better OCR accuracy
  2. Extract text with pytesseract
  3. Parse structured fields with flexible regex patterns
  4. Look up roll_number in legacy_records and compare fields
"""

import os
import re
import math
from typing import Dict, Optional, Any

import cv2
import numpy as np
import pytesseract
from PIL import Image
from db_connect import get_connection

# ── Tesseract path auto-detection (common Mac install locations) ──────────────
for _candidate in [
    "/usr/local/bin/tesseract",
    "/opt/homebrew/bin/tesseract",
    "/usr/bin/tesseract",
]:
    if os.path.isfile(_candidate):
        pytesseract.pytesseract.tesseract_cmd = _candidate
        break


# ── Image preprocessing ───────────────────────────────────────────────────────

def _compute_skew_angle(gray: np.ndarray) -> float:
    """
    Estimate the rotation angle of a document image.
    Uses Hough line detection on edges to find the dominant line angle.
    Returns angle in degrees (0 if detection is inconclusive).
    """
    edges = cv2.Canny(gray, 50, 150, apertureSize=3)
    lines = cv2.HoughLines(edges, 1, np.pi / 180, threshold=200)
    if lines is None:
        return 0.0
    angles = []
    for line in lines[:50]:  # sample up to 50 strongest lines
        theta = line[0][1]
        # Convert from radians to degrees, normalise to [-45, +45] range
        angle = math.degrees(theta) - 90
        if -45 <= angle <= 45:
            angles.append(angle)
    return float(np.median(angles)) if angles else 0.0


def _deskew(gray: np.ndarray) -> np.ndarray:
    """
    Rotate the image to correct for skew.

    Why: photographed or scanned documents are rarely perfectly level.
    Even a 2–3° tilt causes Tesseract's line-segmentation logic to straddle
    two text lines, mixing characters and producing garbage output. Deskewing
    first keeps each text row on a single baseline.
    """
    angle = _compute_skew_angle(gray)
    if abs(angle) < 0.5:          # skip rotation for negligible angles
        return gray
    h, w = gray.shape
    centre = (w / 2, h / 2)
    M = cv2.getRotationMatrix2D(centre, angle, 1.0)
    rotated = cv2.warpAffine(gray, M, (w, h),
                              flags=cv2.INTER_CUBIC,
                              borderMode=cv2.BORDER_REPLICATE)
    return rotated


def preprocess_image(image_path: str) -> np.ndarray:
    """
    Load and preprocess a certificate image to maximise OCR accuracy.

    Steps:
    1. Grayscale conversion — Tesseract works only on single-channel images;
       removing colour eliminates distracting hue differences that look like
       noise to the OCR engine.
    2. Adaptive thresholding — produces a clean black-on-white binary image
       even when lighting is uneven across the page (e.g., a phone photo with
       a bright window on one side). Global thresholding would misclassify
       pixels in darker or brighter regions.
    3. Deskew — corrects rotational tilt so text baselines are horizontal,
       which is a precondition for Tesseract's internal line segmentation.
    """
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"Cannot open image: {image_path}")

    # Step 1 — Grayscale
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)

    # Step 2 — Adaptive threshold (Gaussian-weighted block mean, inverted)
    binary = cv2.adaptiveThreshold(
        gray, 255,
        cv2.ADAPTIVE_THRESH_GAUSSIAN_C,
        cv2.THRESH_BINARY,
        blockSize=31,   # neighbourhood block size (must be odd)
        C=10,           # constant subtracted from the mean
    )

    # Step 3 — Deskew
    deskewed = _deskew(binary)
    return deskewed


# ── Text extraction ───────────────────────────────────────────────────────────

def extract_text(image_path: str) -> str:
    """
    Run Tesseract OCR on a preprocessed certificate image and return raw text.

    Uses --oem 3 (best available LSTM engine) and --psm 6 (uniform block of
    text), which works well for structured certificate documents where text
    flows in consistent rows rather than columns or tables.
    """
    processed = preprocess_image(image_path)
    # Convert numpy array back to PIL Image for pytesseract
    pil_img = Image.fromarray(processed)
    config = "--oem 3 --psm 6"
    return pytesseract.image_to_string(pil_img, config=config)


# ── Field extraction ──────────────────────────────────────────────────────────

def extract_fields(raw_text: str) -> Dict[str, str]:
    """
    Parse structured fields from noisy OCR output using flexible regex patterns.

    All patterns are case-insensitive and tolerate common OCR misreadings:
    - 'Roll No:', 'Roll Number -', 'Roll:' all match the roll_number pattern
    - 'Name:', 'Student Name:', 'Full Name -' all match the name pattern
    - 'Grade:', 'CGPA:', 'GPA -' all match the grade pattern

    The roll_number pattern accepts both letters and digits since alphanumeric
    IDs like 'CS2019045' are typical, but OCR sometimes confuses '0' with 'O'.
    """
    fields: Dict[str, str] = {}

    # Roll number: "Roll No:", "Roll Number -", "Roll:", "Roll#", etc.
    roll_match = re.search(
        r"Roll\s*(?:No\.?|Number|Num\.?|#)?\s*[:\-]?\s*((?=[A-Z0-9]*\d)[A-Z0-9]{4,20})",
        raw_text,
        re.IGNORECASE,
    )
    if roll_match:
        fields["roll_number"] = roll_match.group(1).strip()

    # Student name: "Name:", "Student Name -", "Full Name:", "Student:"
    name_match = re.search(
        r"(?:Student\s+)?(?:Full\s+)?Name\s*[:\-]?\s*([A-Za-z](?:[A-Za-z .'-]{1,60}))",
        raw_text,
        re.IGNORECASE,
    )
    if name_match:
        # Strip trailing noise (numbers, punctuation etc. from OCR overshoot)
        raw_name = name_match.group(1).strip()
        raw_name = re.sub(r"[^A-Za-z .\'-]+.*$", "", raw_name).strip()
        if raw_name:
            fields["student_name"] = raw_name

    # Grade / CGPA / GPA: "Grade: 8.40", "CGPA - 8.4", "GPA: 9"
    grade_match = re.search(
        r"(?:Grade|CGPA|GPA|Score)\s*[:\-]?\s*([0-9]+(?:\.[0-9]{1,2})?)",
        raw_text,
        re.IGNORECASE,
    )
    if grade_match:
        fields["grade"] = grade_match.group(1).strip()

    return fields



def extract_text_best(image_path: str) -> str:
    """
    Try several preprocessing variants and return the first OCR text from which
    a roll number can be extracted: plain grayscale, then Otsu threshold, then
    the full pipeline (adaptive threshold + deskew) as a last resort.

    Why: aggressive thresholding can corrupt clean, high-resolution images
    (e.g. reading 'C' as a euro sign), while it helps on uneven phone photos.
    """
    img = cv2.imread(image_path)
    if img is None:
        raise FileNotFoundError(f"Cannot open image: {image_path}")
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    otsu = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]
    for candidate in (gray, otsu):
        text = pytesseract.image_to_string(
            Image.fromarray(candidate), config="--oem 3 --psm 6"
        )
        if "roll_number" in extract_fields(text):
            return text
    return extract_text(image_path)


# ── Main check function ───────────────────────────────────────────────────────

def check_legacy_certificate(
    image_path: str,
    institution_id: int,
) -> Dict[str, Any]:
    """
    Verify a legacy paper certificate image against the institution's records.

    Parameters
    ----------
    image_path : str
        Path to the scanned/photographed certificate image.
    institution_id : int
        The institution whose legacy_records table to check against.

    Returns
    -------
    dict with "status" key:
        "unreadable"    — roll number could not be extracted from image
        "forgery_flag"  — roll number or field values don't match records
        "verified"      — all extractable fields match the institution record
    """
    raw_text = extract_text_best(image_path)
    extracted = extract_fields(raw_text)

    if "roll_number" not in extracted:
        return {
            "status": "unreadable",
            "message": "Could not extract a roll number from the image.",
            "raw_text_preview": raw_text[:300],
        }

    roll_number = extracted["roll_number"]

    conn = get_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT * FROM legacy_records
            WHERE institution_id = %s AND roll_number = %s
            LIMIT 1;
            """,
            (institution_id, roll_number),
        )
        record = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    if record is None:
        return {
            "status": "forgery_flag",
            "message": f"No institution record found for roll number '{roll_number}'.",
            "extracted": extracted,
        }

    # Compare extractable fields
    mismatches = []

    if "student_name" in extracted:
        # Case-insensitive substring match — OCR names are rarely perfect
        ocr_name = extracted["student_name"].lower().strip()
        db_name  = (record["student_name"] or "").lower().strip()
        # Accept if the OCR name is a substring of the DB name or vice-versa
        if ocr_name not in db_name and db_name not in ocr_name:
            mismatches.append(
                f"student_name (OCR: '{extracted['student_name']}', record: '{record['student_name']}')"
            )

    if "grade" in extracted:
        try:
            ocr_grade = float(extracted["grade"])
            db_grade  = float(record["grade"])
            # Allow ±0.05 tolerance for common OCR digit-recognition errors
            if abs(ocr_grade - db_grade) > 0.05:
                mismatches.append(
                    f"grade (OCR: {extracted['grade']}, record: {record['grade']})"
                )
        except (ValueError, TypeError):
            mismatches.append(f"grade (unparseable OCR value: '{extracted['grade']}')")

    if mismatches:
        return {
            "status": "forgery_flag",
            "message": f"Mismatched fields: {', '.join(mismatches)}",
            "extracted": extracted,
            "institution_record": {k: str(v) for k, v in record.items()},
        }

    return {
        "status": "verified",
        "message": "All extractable fields match the institution record.",
        "extracted": extracted,
        "institution_record": {k: str(v) for k, v in record.items()},
    }


# ── CLI ───────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys
    import json

    img  = sys.argv[1] if len(sys.argv) > 1 else "sample_data/sample_legacy_cert.png"
    inst = int(sys.argv[2]) if len(sys.argv) > 2 else 1
    result = check_legacy_certificate(img, inst)
    print(json.dumps(result, indent=2, default=str))