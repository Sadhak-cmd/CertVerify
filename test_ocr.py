from legacy_check import extract_text, extract_fields, check_legacy_certificate

def check(name, ok):
    print(("PASS  " if ok else "FAIL  ") + name)

# 1. Raw OCR quality: look at this output yourself
raw = extract_text("sample_data/sample_legacy_cert.png")
print("---- RAW OCR TEXT ----"); print(raw); print("----------------------")

# 2. Field extraction
f = extract_fields(raw)
print("Extracted:", f)
check("roll number extracted correctly", f.get("roll_number") == "CS2019045")
check("name extracted", "riya" in f.get("student_name", "").lower())
check("grade extracted", f.get("grade") in ("8.4", "8.40"))

# 3. Full pipeline outcomes
r = check_legacy_certificate("sample_data/sample_legacy_cert.png", 1)
check("genuine cert -> verified", r["status"] == "verified")

r = check_legacy_certificate("sample_data/sample_tampered_cert.png", 1)
check("tampered grade -> forgery_flag", r["status"] == "forgery_flag" and "grade" in r["message"])

# 4. Same roll number checked against the wrong institution -> no record found
r = check_legacy_certificate("sample_data/sample_legacy_cert.png", 2)
check("wrong institution -> forgery_flag (no record)", r["status"] == "forgery_flag")
print("   message:", r["message"])