"""
make_sample_certificate.py
Generates clean, high-contrast certificate images specifically designed for reliable
OCR-based demo testing. These synthetic images avoid the messiness of real photo OCR.
"""

import os
from PIL import Image, ImageDraw, ImageFont


def create_sample_certificate(
    output_filename: str = "sample_legacy_cert.png",
    student_name: str = "Riya Sharma",
    roll_number: str = "CS2019045",
    course_name: str = "B.Tech Computer Science",
    grade: str = "8.40",
    issue_date: str = "2019-06-15",
    institution_name: str = "ABC University",
) -> str:
    """
    Generate an OCR-friendly certificate image and save it in sample_data/.

    Returns
    -------
    str
        The file path of the generated certificate image.
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    sample_dir = os.path.join(base_dir, "sample_data")
    os.makedirs(sample_dir, exist_ok=True)
    out_path = os.path.join(sample_dir, output_filename)

    # Large image dimensions make text bigger → better OCR accuracy
    width, height = 1200, 800
    image = Image.new("RGB", (width, height), color=(255, 255, 255))
    draw = ImageDraw.Draw(image)

    # Outer border for visual structure
    draw.rectangle([(20, 20), (width - 20, height - 20)], outline=(0, 0, 0), width=5)
    draw.rectangle([(30, 30), (width - 30, height - 30)], outline=(80, 80, 80), width=2)

    # Try TrueType fonts on macOS, fall back gracefully to default
    try:
        font_title  = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 40)
        font_sub    = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 22)
        font_label  = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 28)
        font_value  = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 28)
        font_footer = ImageFont.truetype("/System/Library/Fonts/Helvetica.ttc", 17)
    except IOError:
        font_title = font_sub = font_label = font_value = font_footer = ImageFont.load_default()

    # Title block
    draw.text((width // 2, 90),  institution_name.upper(),  fill=(0, 0, 0), font=font_title,  anchor="mm")
    draw.text((width // 2, 145), "CERTIFICATE OF COMPLETION",               fill=(0, 0, 0), font=font_sub,   anchor="mm")
    draw.line([(80, 175), (width - 80, 175)], fill=(0, 0, 0), width=2)

    # Field rows — LABEL_WIDTH chosen so labels don't bleed into values
    LABEL_X = 120
    VALUE_X = 420
    START_Y = 235
    LINE_H  = 72

    fields = [
        ("Name",       student_name),
        ("Roll No",    roll_number),
        ("Course",     course_name),
        ("Grade",      grade),
        ("Issue Date", issue_date),
    ]

    for i, (label, value) in enumerate(fields):
        y = START_Y + i * LINE_H
        draw.text((LABEL_X, y), f"{label} :", fill=(0, 0, 0), font=font_label)
        draw.text((VALUE_X, y), value,        fill=(0, 0, 0), font=font_value)

    # Footer
    draw.line([(80, height - 110), (width - 80, height - 110)], fill=(0, 0, 0), width=1)
    draw.text(
        (width // 2, height - 70),
        "Official Digitized Archive — Department of Academic Records",
        fill=(80, 80, 80),
        font=font_footer,
        anchor="mm",
    )

    image.save(out_path)
    print(f"Sample certificate saved to {out_path}")
    return out_path


if __name__ == "__main__":
    # Legitimate certificate (matches DB seed data)
    create_sample_certificate()
    # Tampered version — same roll number, wrong grade — useful for testing forgery detection
    create_sample_certificate(
        output_filename="sample_tampered_cert.png",
        student_name="Riya Sharma",
        roll_number="CS2019045",
        grade="9.90",
        issue_date="2019-06-15",
    )
    print("Both sample certificates generated in sample_data/")
