"""
seed_demo.py - populate CertVerify with fictional demo data.

For each of 10 institutions (your 2 existing ones + 8 new):
  * ~50 students, each with a signed digital certificate
  * ~25 legacy (paper-era) records for the OCR check
  * a few revocations (so the REVOKED demo has material)
Then it publishes every institution's key + signed revocation list and pins/syncs them
into verifier_store/, so every credential verifies straight away.

Run from the project folder (venv active):
    python seed_demo.py --dry-run      # prints the plan, touches nothing
    python seed_demo.py --images       # does it; --images also writes sample legacy certificates

Safe to re-run: existing institutions, roll numbers and legacy records are skipped.
All names are fictional.   Python 3.8 compatible.
"""

import argparse
import datetime
import os
import random

INSTITUTIONS = [
    # (name, issuer_account, roll prefix, courses)
    ("ABC University", "abc_univ_01", "ABC",
     ["B.Tech Computer Science", "B.Tech Electronics", "B.Sc Data Science"]),
    ("National Business School", "nbs_02", "NBS",
     ["MBA Finance", "MBA Marketing", "MBA Operations"]),
    ("Western Institute of Technology", "wit_03", "WIT",
     ["B.Tech Mechanical Engineering", "B.Tech Civil Engineering", "B.Tech Information Technology"]),
    ("Lakeshore College of Arts and Science", "lcas_04", "LCA",
     ["B.A. Economics", "B.Sc Physics", "B.A. English Literature"]),
    ("Meridian Institute of Engineering", "mie_05", "MIE",
     ["B.Tech Electrical Engineering", "B.Tech Computer Engineering", "M.Tech VLSI Design"]),
    ("Sahyadri Medical Academy", "sma_06", "SMA",
     ["B.Sc Nursing", "B.Pharm", "B.Sc Medical Laboratory Technology"]),
    ("Deccan Law School", "dls_07", "DLS",
     ["LL.B", "B.A. LL.B", "LL.M Corporate Law"]),
    ("Horizon Institute of Aerospace Studies", "hias_08", "HIA",
     ["B.Tech Aerospace Engineering", "M.Tech Avionics", "B.Sc Aviation Technology"]),
    ("Riverbend Polytechnic", "rbp_09", "RBP",
     ["Diploma Mechanical Engineering", "Diploma Computer Engineering", "Diploma Electronics"]),
    ("Pinnacle School of Management", "psm_10", "PSM",
     ["MBA Human Resources", "MBA Business Analytics", "BBA"]),
]

FIRST = ["Aarav", "Vivaan", "Aditya", "Arjun", "Rohan", "Karan", "Ishaan", "Nikhil", "Rahul", "Siddharth",
         "Varun", "Yash", "Harsh", "Dev", "Manav", "Tanmay", "Omkar", "Pranav", "Sahil", "Neel",
         "Ananya", "Diya", "Isha", "Kavya", "Meera", "Neha", "Pooja", "Riya", "Saanvi", "Shruti",
         "Tanvi", "Aditi", "Bhavna", "Chaitra", "Divya", "Gauri", "Janhavi", "Kritika", "Lavanya", "Mrunal",
         "Nandini", "Prerana", "Radhika", "Sakshi", "Trisha", "Urvi", "Vaidehi", "Yamini", "Zoya", "Aisha"]
LAST = ["Sharma", "Verma", "Patil", "Kulkarni", "Deshmukh", "Joshi", "Nair", "Menon", "Iyer", "Reddy",
        "Rao", "Gupta", "Singh", "Khan", "Mehta", "Shah", "Desai", "Kapoor", "Bhatt", "Chopra",
        "Jain", "Agarwal", "Pillai", "Bose", "Das", "Banerjee", "Naik", "Gaikwad", "Pawar", "More",
        "Shinde", "Jadhav", "Thakur", "Malhotra", "Saxena", "Sinha", "Rane", "Sawant", "Kamat", "Fernandes"]
REASONS = ["Issued in error", "Academic misconduct finding", "Duplicate record issued", "Course result withdrawn"]

FONT_CANDIDATES = [
    "/Library/Fonts/Arial.ttf", "/System/Library/Fonts/Supplemental/Arial.ttf",
    "/System/Library/Fonts/Helvetica.ttc", "C:/Windows/Fonts/arial.ttf",
    "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf",
]


def make_people(rng, count, used_names):
    people = []
    while len(people) < count:
        name = "%s %s" % (rng.choice(FIRST), rng.choice(LAST))
        if name in used_names:
            continue
        used_names.add(name)
        people.append(name)
    return people


def make_roll(rng, prefix, year, used_rolls):
    while True:
        roll = "%s%d%03d" % (prefix, year, rng.randint(1, 999))
        if roll not in used_rolls:
            used_rolls.add(roll)
            return roll


def rand_date(rng, start, end):
    return start + datetime.timedelta(days=rng.randint(0, (end - start).days))


def build_plan(rng, used_rolls, per_inst, legacy_per_inst):
    """Pure data generation: no database."""
    used_names = set()
    plan = []
    for name, account, prefix, courses in INSTITUTIONS:
        students = []
        for person in make_people(rng, per_inst, used_names):
            year = rng.choice([2022, 2023, 2024])
            students.append({
                "name": person,
                "roll": make_roll(rng, prefix, year, used_rolls),
                "course": rng.choice(courses),
                "grade": round(rng.uniform(6.0, 9.9), 2),
                "date": rand_date(rng, datetime.date(2023, 6, 1), datetime.date(2025, 6, 30)),
            })
        legacy = []
        for person in make_people(rng, legacy_per_inst, used_names):
            year = rng.choice([2016, 2017, 2018, 2019, 2020])
            legacy.append({
                "name": person,
                "roll": make_roll(rng, prefix, year, used_rolls),
                "course": rng.choice(courses),
                "grade": round(rng.uniform(5.5, 9.8), 2),
                "date": rand_date(rng, datetime.date(year, 5, 1), datetime.date(year, 7, 31)),
            })
        plan.append({"name": name, "account": account, "prefix": prefix,
                     "students": students, "legacy": legacy})
    return plan


def write_sample_image(path, inst_name, rec, grade):
    """Plain, OCR-friendly certificate image. Best effort; returns False if no usable font."""
    try:
        from PIL import Image, ImageDraw, ImageFont
    except ImportError:
        return False
    font = None
    for candidate in FONT_CANDIDATES:
        if os.path.exists(candidate):
            try:
                font, big = ImageFont.truetype(candidate, 44), ImageFont.truetype(candidate, 56)
                break
            except Exception:
                continue
    if font is None:
        return False
    img = Image.new("RGB", (1400, 900), "white")
    d = ImageDraw.Draw(img)
    d.text((90, 90), inst_name, fill="black", font=big)
    d.text((90, 190), "Certificate of Completion", fill="black", font=font)
    rows = [("Roll No", rec["roll"]), ("Name", rec["name"]), ("Course", rec["course"]),
            ("Grade", "%.2f" % grade), ("Date", rec["date"].isoformat())]
    y = 330
    for label, value in rows:
        d.text((90, y), "%s: %s" % (label, value), fill="black", font=font)
        y += 90
    img.save(path)
    return True


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--per-institution", type=int, default=50, help="students (digital certificates) per institution")
    ap.add_argument("--legacy", type=int, default=25, help="legacy records per institution")
    ap.add_argument("--revoke", type=int, default=2, help="certificates to revoke per institution")
    ap.add_argument("--seed", type=int, default=2026, help="random seed (same seed = same data)")
    ap.add_argument("--images", action="store_true", help="also write sample legacy certificate images")
    ap.add_argument("--dry-run", action="store_true", help="print the plan only")
    args = ap.parse_args()

    rng = random.Random(args.seed)
    used_rolls = set()

    if args.dry_run:
        plan = build_plan(rng, used_rolls, args.per_institution, args.legacy)
        for p in plan:
            print("%-42s %3d students, %3d legacy | e.g. %s %s (%s, %.2f)" % (
                p["name"], len(p["students"]), len(p["legacy"]),
                p["students"][0]["roll"], p["students"][0]["name"], p["students"][0]["course"], p["students"][0]["grade"]))
        print("\nDry run only: nothing was written.")
        return

    # Real run: imports here so --dry-run works anywhere.
    from db_connect import get_connection
    from issue_signed_certificate import sign_certificate
    from revoke_certificate import revoke_certificate
    import publisher

    conn = get_connection()
    cur = conn.cursor()
    cur.execute("SELECT roll_number FROM students")
    used_rolls.update(r[0] for r in cur.fetchall())
    cur.execute("SELECT roll_number FROM legacy_records")
    used_rolls.update(r[0] for r in cur.fetchall())

    plan = build_plan(rng, used_rolls, args.per_institution, args.legacy)
    img_dir = os.path.join("sample_data", "demo_legacy")
    if args.images:
        os.makedirs(img_dir, exist_ok=True)

    totals = {"students": 0, "signed": 0, "legacy": 0, "revoked": 0, "failed": 0}
    for p in plan:
        # 1. institution
        cur.execute("SELECT institution_id FROM institutions WHERE issuer_account = %s", (p["account"],))
        row = cur.fetchone()
        if row:
            inst_id = row[0]
        else:
            try:
                cur.execute("INSERT INTO institutions (name, issuer_account) VALUES (%s, %s)", (p["name"], p["account"]))
            except Exception:
                cur.execute("INSERT INTO institutions (name, issuer_account, public_key) VALUES (%s, %s, %s)",
                            (p["name"], p["account"], ""))
            conn.commit()
            inst_id = cur.lastrowid
        # an existing institution by name keeps its id; ensure the plan matches it
        print("== %s (institution_id=%s)" % (p["name"], inst_id))

        # 2. students + signed certificates
        new_certs = []
        for s in p["students"]:
            cur.execute("INSERT INTO students (name, roll_number) VALUES (%s, %s)", (s["name"], s["roll"]))
            student_id = cur.lastrowid
            cur.execute(
                "INSERT INTO certificates (student_id, institution_id, course_name, grade, issue_date) "
                "VALUES (%s, %s, %s, %s, %s)",
                (student_id, inst_id, s["course"], s["grade"], s["date"]))
            conn.commit()
            cert_id = cur.lastrowid
            totals["students"] += 1
            try:
                sign_certificate(cert_id, inst_id)
                new_certs.append(cert_id)
                totals["signed"] += 1
            except Exception as exc:
                totals["failed"] += 1
                print("   signing failed for cert %s: %s" % (cert_id, exc))

        # 3. legacy records
        for rec in p["legacy"]:
            cur.execute(
                "INSERT INTO legacy_records (institution_id, student_name, roll_number, course_name, grade, issue_date) "
                "VALUES (%s, %s, %s, %s, %s, %s)",
                (inst_id, rec["name"], rec["roll"], rec["course"], rec["grade"], rec["date"]))
            totals["legacy"] += 1
        conn.commit()

        # 4. a few revocations
        for cert_id in new_certs[:args.revoke]:
            try:
                revoke_certificate(cert_id, rng.choice(REASONS))
                totals["revoked"] += 1
            except Exception as exc:
                print("   revoke failed for cert %s: %s" % (cert_id, exc))

        # 5. publish key info + signed revocation list; pin and download for the verifier
        publisher.publish_all(inst_id, trust=True, sync=True)

        # 6. optional sample images: one genuine, one tampered (grade changed)
        if args.images and p["legacy"]:
            rec = p["legacy"][0]
            ok1 = write_sample_image(os.path.join(img_dir, "genuine_%s.png" % p["prefix"]), p["name"], rec, rec["grade"])
            ok2 = write_sample_image(os.path.join(img_dir, "tampered_%s.png" % p["prefix"]), p["name"], rec,
                                     min(9.9, rec["grade"] + 0.7))
            if not (ok1 and ok2):
                print("   (no usable font/Pillow: skipped sample images)")

    conn.close()
    print("\nDone: %(students)d students, %(signed)d signed certificates, %(legacy)d legacy records, "
          "%(revoked)d revocations, %(failed)d signing failures." % totals)
    if args.images:
        print("Sample legacy images are in %s" % img_dir)


if __name__ == "__main__":
    main()
