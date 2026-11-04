"""
CBL-05 demo app: issuer, holder wallet, verifier, legacy-certificate check.

Run with:   python app.py      then open http://127.0.0.1:5050

This file only wires routes to the existing modules (it does not duplicate their logic):
    issue_signed_certificate.sign_certificate(cert_id, institution_id) -> dict
    verify_credential.verify_credential(path) -> valid | revoked | revocation_unconfirmed | invalid |
                                                 untrusted_key | unknown_institution   (NO database, NO network)
    revoke_certificate.revoke_certificate(cert_id, reason), revoke_certificate.is_revoked(cert_id)
    presentation.create_presentation(path) -> minimal shareable proof (course + date only)
    publisher.publish_all(institution_id)  -> published/ key info + signed revocation list
    trust_store.refresh_from_published()   -> verifier "downloads" the latest revocation list
    make_qr.generate_qr(path) -> out_path
    legacy_check.check_legacy_certificate(image_path, institution_id) -> dict

Python 3.8 compatible.
"""

import json
import os
import re
import uuid
from datetime import date

from flask import (Flask, abort, redirect, render_template_string, request,
                   send_from_directory)

from db_connect import get_connection
import issue_signed_certificate
import legacy_check
import make_qr
import presentation
import publisher
import revoke_certificate
import trust_store
import verify_credential as verify_module

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CRED_DIR = os.path.join(BASE_DIR, "credentials")
UPLOAD_DIR = os.path.join(BASE_DIR, "sample_data", "uploads")
os.makedirs(CRED_DIR, exist_ok=True)
os.makedirs(UPLOAD_DIR, exist_ok=True)

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024  # 25 MB: phone photos are often 5-12 MB
MAX_IMAGE_SIDE = 2400  # longest side, in pixels, sent to OCR

# --------------------------------------------------------------------------
# Layout and shared helpers
# --------------------------------------------------------------------------

LAYOUT = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{ title }} | CertVerify</title>
<link rel="stylesheet" href="{{ url_for('static', filename='style.css') }}">
</head><body>
<a class="skip" href="#content">Skip to content</a>
<header class="site-header">
  <div class="rosette-band" aria-hidden="true"></div>
  <div class="bar">
    <a class="brand" href="/">
      <svg viewBox="0 0 48 48" aria-hidden="true" focusable="false">
        <g fill="none" stroke="currentColor" stroke-width="1.1">
          <ellipse cx="24" cy="24" rx="21" ry="8"/>
          <ellipse cx="24" cy="24" rx="21" ry="8" transform="rotate(30 24 24)"/>
          <ellipse cx="24" cy="24" rx="21" ry="8" transform="rotate(60 24 24)"/>
          <ellipse cx="24" cy="24" rx="21" ry="8" transform="rotate(90 24 24)"/>
          <ellipse cx="24" cy="24" rx="21" ry="8" transform="rotate(120 24 24)"/>
          <ellipse cx="24" cy="24" rx="21" ry="8" transform="rotate(150 24 24)"/>
        </g>
        <circle cx="24" cy="24" r="12" fill="#fffdf7" stroke="currentColor" stroke-width="1.6"/>
        <path d="M18 24.5l4.2 4.2L30.5 19" fill="none" stroke="currentColor" stroke-width="3" stroke-linecap="round" stroke-linejoin="round"/>
      </svg>
      <span><span class="brand-name">CertVerify</span></span>
    </a>
    {% set p = request.path %}
    <nav class="site-nav" aria-label="Main">
      <a href="/issuer"{% if p == '/issuer' %} aria-current="page"{% endif %}>Issuer</a>
      <a href="/holder"{% if p.startswith('/holder') %} aria-current="page"{% endif %}>Holder</a>
      <a href="/verifier"{% if p == '/verifier' or p == '/verifier/refresh' %} aria-current="page"{% endif %}>Verifier</a>
      <a href="/verifier/legacy"{% if p.startswith('/verifier/legacy') %} aria-current="page"{% endif %}>Legacy check</a>
      <a class="nav-aux" href="/issuer/revoke"{% if p.startswith('/issuer/revoke') %} aria-current="page"{% endif %}>Revoke</a>
    </nav>
  </div>
</header>
<span id="content" tabindex="-1"></span>
<main>{{ body|safe }}</main>
<footer class="site-footer"><div class="inner">
  <span>CertVerify</span>
  <span>Signatures are checked locally against pinned institution keys and a signed revocation list.</span>
</div></footer>
</body></html>"""


def page(title, body_tpl, **ctx):
    """Render a body template, then wrap it in the shared layout."""
    body = render_template_string(body_tpl, **ctx)
    return render_template_string(LAYOUT, title=title, body=body)


def _columns(cur_rows):
    return list(cur_rows[0].keys()) if cur_rows else []


def _pick(cols, *needles):
    """Return the first column whose name contains one of the needles."""
    for needle in needles:
        for col in cols:
            if needle in col.lower():
                return col
    return None


def _cred_path(cert_id):
    return os.path.join(CRED_DIR, "credential_{}.json".format(cert_id))


def _qr_path(cert_id):
    return os.path.join(CRED_DIR, "credential_{}_qr.png".format(cert_id))


def _pres_path(cert_id):
    return os.path.join(CRED_DIR, "presentation_{}.json".format(cert_id))


def _pres_qr_path(cert_id):
    return os.path.join(CRED_DIR, "presentation_{}_qr.png".format(cert_id))


def _ensure_presentation(cert_id):
    """Create the minimal shareable proof (and its QR) from the full credential if missing."""
    if not os.path.exists(_cred_path(cert_id)):
        return False
    try:
        if not os.path.exists(_pres_path(cert_id)):
            presentation.create_presentation(_cred_path(cert_id), out_path=_pres_path(cert_id))
        if not os.path.exists(_pres_qr_path(cert_id)):
            make_qr.generate_qr(_pres_path(cert_id))
    except Exception:
        return False
    return os.path.exists(_pres_path(cert_id))


def _rec_get(rec, *names):
    """Read a field from whatever is_revoked() returns (dict, namedtuple, dataclass)."""
    for name in names:
        if isinstance(rec, dict) and name in rec:
            return rec[name]
        if hasattr(rec, name):
            return getattr(rec, name)
    return None


def _load_choices():
    """Students and institutions for dropdowns. Column names are detected, not assumed."""
    students, institutions = [], []
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute("SELECT * FROM students ORDER BY 1 DESC LIMIT 300")
        rows = cur.fetchall()
        cols = _columns(rows)
        name_col, roll_col = _pick(cols, "name"), _pick(cols, "roll")
        for r in rows:
            label = str(r.get("student_id"))
            if name_col:
                label += " - {}".format(r[name_col])
            if roll_col:
                label += " ({})".format(r[roll_col])
            students.append({"id": r.get("student_id"), "label": label})

        cur.execute("SELECT * FROM institutions ORDER BY 1")
        rows = cur.fetchall()
        cols = _columns(rows)
        inst_name = _pick(cols, "name")
        for r in rows:
            label = str(r.get("institution_id"))
            if inst_name:
                label += " - {}".format(r[inst_name])
            institutions.append({"id": r.get("institution_id"), "label": label})
    finally:
        conn.close()
    return students, institutions


def _revocation_pill(cert_id):
    try:
        return "bad" if revoke_certificate.is_revoked(cert_id) else "ok"
    except Exception:
        return "none"


# --------------------------------------------------------------------------
# Home
# --------------------------------------------------------------------------

HOME_TPL = """
<h1>Academic certificate verification</h1>
<p class="sub">Digitally signed credentials and legacy paper-certificate checks, with no per-certificate lookup.</p>
<div class="tiles">
  <a class="tile" href="/issuer">
    <span class="tile-num" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="12" rx="1"/><path d="M7 8h6M7 11h3"/><circle cx="16.5" cy="12" r="2"/><path d="M15.5 13.8L15 20l1.5-1 1.5 1-.5-6.2"/></svg></span><span class="tile-go" aria-hidden="true">&rarr;</span>
    <span class="tile-body"><span class="tile-title">Issuer</span>
      <span class="tile-desc">Issue and sign a new certificate</span></span>
  </a>
  <a class="tile" href="/issuer/revoke">
    <span class="tile-num" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="16" rx="1"/><path d="M7 9h10M7 13h6"/><path d="M4 21L20 3"/></svg></span><span class="tile-go" aria-hidden="true">&rarr;</span>
    <span class="tile-body"><span class="tile-title">Revoke</span>
      <span class="tile-desc">Revoke a certificate (hash-chained log)</span></span>
  </a>
  <a class="tile" href="/holder">
    <span class="tile-num" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M3 7a2 2 0 0 1 2-2h12v3"/><rect x="3" y="7" width="18" height="13" rx="2"/><path d="M16 13.5h2"/></svg></span><span class="tile-go" aria-hidden="true">&rarr;</span>
    <span class="tile-body"><span class="tile-title">Holder wallet</span>
      <span class="tile-desc">Download your credential and a minimal shareable proof (QR) by roll number</span></span>
  </a>
  <a class="tile" href="/verifier">
    <span class="tile-num" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3l8 3v6c0 4.5-3.2 8-8 9-4.8-1-8-4.5-8-9V6z"/><path d="M8.5 12l2.5 2.5 4.5-5"/></svg></span><span class="tile-go" aria-hidden="true">&rarr;</span>
    <span class="tile-body"><span class="tile-title">Verifier</span>
      <span class="tile-desc">Verify a credential locally: no database, no per-certificate lookup</span></span>
  </a>
  <a class="tile" href="/verifier/legacy">
    <span class="tile-num" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M6 3h8l4 4v14H6z"/><path d="M14 3v4h4"/><path d="M9 12h6M9 15h6M9 18h4"/></svg></span><span class="tile-go" aria-hidden="true">&rarr;</span>
    <span class="tile-body"><span class="tile-title">Legacy check (OCR)</span>
      <span class="tile-desc">Photograph or upload a paper certificate and match it against institution records</span></span>
  </a>
</div>
"""


@app.route("/")
def home():
    return page("Home", HOME_TPL)


# --------------------------------------------------------------------------
# 1. Issuer
# --------------------------------------------------------------------------

ISSUER_TPL = """
<h1>Issuer</h1>
<p class="sub">Issue a certificate and sign it with the institution's private key.</p>

{% if error %}<div class="banner invalid"><b>Could not issue</b>{{ error }}</div>{% endif %}

{% if issued %}
<div class="banner valid"><b>Certificate #{{ issued.cert_id }} issued and signed</b>
  Verifiers check it against the institution's pinned public key, with no database lookup.</div>
<div class="card">
  <p><a class="btn" href="/credentials/credential_{{ issued.cert_id }}.json">Download full credential (private copy)</a>
     {% if issued.proof %}<a class="btn" href="/credentials/presentation_{{ issued.cert_id }}.json">Download shareable proof</a>{% endif %}</p>
  <p class="muted">The full credential holds the grade and student details for the holder. The shareable proof
     reveals only the course and issue date, and still verifies.</p>
  {% if issued.qr %}
    <p>QR code of the shareable proof:</p>
    <img class="qr" src="/credentials/presentation_{{ issued.cert_id }}_qr.png" alt="QR code">
  {% else %}
    <p class="muted">QR code could not be generated for this credential.</p>
  {% endif %}
</div>
{% endif %}

<div class="card">
<form method="post">
  <label>Student</label>
  <select name="student_id" required>
    {% for s in students %}<option value="{{ s.id }}" {% if form.get('student_id') == s.id|string %}selected{% endif %}>{{ s.label }}</option>{% endfor %}
  </select>
  <label>Institution</label>
  <select name="institution_id" required>
    {% for i in institutions %}<option value="{{ i.id }}" {% if form.get('institution_id') == i.id|string %}selected{% endif %}>{{ i.label }}</option>{% endfor %}
  </select>
  <label>Course name</label>
  <input name="course_name" value="{{ form.get('course_name', '') }}" required>
  <label>Grade</label>
  <input name="grade" type="number" step="0.01" min="0" max="99.99" value="{{ form.get('grade', '') }}" required>
  <label>Issue date</label>
  <input name="issue_date" type="date" value="{{ form.get('issue_date', '') }}" required>
  <button type="submit">Issue and sign</button>
</form>
</div>
"""


@app.route("/issuer", methods=["GET", "POST"])
def issuer():
    try:
        students, institutions = _load_choices()
    except Exception as exc:
        return page("Issuer", ISSUER_TPL, students=[], institutions=[], form={}, issued=None,
                    error="Database error while loading students/institutions: {}".format(exc))

    if request.method == "GET":
        return page("Issuer", ISSUER_TPL, students=students, institutions=institutions,
                    form={}, issued=None, error=None)

    form = request.form
    ctx = dict(students=students, institutions=institutions, form=form, issued=None)

    missing = [f for f in ("student_id", "institution_id", "course_name", "grade", "issue_date")
               if not form.get(f, "").strip()]
    if missing:
        return page("Issuer", ISSUER_TPL, error="Missing fields: {}".format(", ".join(missing)), **ctx)

    try:
        student_id = int(form["student_id"])
        institution_id = int(form["institution_id"])
        grade = float(form["grade"])
        issue_date = date.fromisoformat(form["issue_date"].strip())
    except ValueError:
        return page("Issuer", ISSUER_TPL, error="Student/institution must be numbers, grade a number, "
                    "and the date in YYYY-MM-DD format.", **ctx)
    course_name = form["course_name"].strip()

    conn = get_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO certificates (student_id, institution_id, course_name, grade, issue_date) "
            "VALUES (%s, %s, %s, %s, %s)",
            (student_id, institution_id, course_name, grade, issue_date),
        )
        conn.commit()
        cert_id = cur.lastrowid
    except Exception as exc:
        return page("Issuer", ISSUER_TPL, error="Database error inserting certificate: {}".format(exc), **ctx)
    finally:
        conn.close()

    try:
        issue_signed_certificate.sign_certificate(cert_id, institution_id)
    except Exception as exc:
        return page("Issuer", ISSUER_TPL,
                    error="Certificate #{} was saved but signing failed: {}".format(cert_id, exc), **ctx)

    proof_ok = _ensure_presentation(cert_id)
    qr_ok = proof_ok and os.path.exists(_pres_qr_path(cert_id))
    try:
        publisher.publish_all(institution_id)   # (re)publish key info + signed revocation list
    except Exception:
        pass

    ctx["issued"] = {"cert_id": cert_id, "qr": qr_ok, "proof": proof_ok}
    ctx["form"] = {}
    return page("Issuer", ISSUER_TPL, error=None, **ctx)


# --------------------------------------------------------------------------
# 2. Revocation
# --------------------------------------------------------------------------

REVOKE_TPL = """
<h1>Revoke a certificate</h1>
<p class="sub">Revocations are appended to a hash-chained log and published in a signed revocation list.</p>

{% if message %}<div class="banner {{ css }}"><b>{{ headline }}</b>{{ message }}</div>{% endif %}

<div class="card">
<form method="post">
  <label>Certificate ID</label>
  <input name="cert_id" type="number" min="1" value="{{ form.get('cert_id', '') }}" required>
  <label>Reason</label>
  <input name="reason" maxlength="255" value="{{ form.get('reason', '') }}" required>
  <button class="danger" type="submit">Revoke</button>
</form>
</div>

<div class="card">
  <b>Recently signed certificates</b>
  <table>
    <tr><th>ID</th><th>Course</th><th>Issued</th><th>Status</th></tr>
    {% for r in recent %}
    <tr><td>{{ r.cert_id }}</td><td>{{ r.course_name }}</td><td>{{ r.issue_date }}</td>
        <td><span class="pill {{ r.pill }}">{{ 'REVOKED' if r.pill == 'bad' else ('active' if r.pill == 'ok' else '?') }}</span></td></tr>
    {% else %}<tr><td colspan="4" class="muted">No signed certificates yet.</td></tr>{% endfor %}
  </table>
</div>
"""


def _recent_signed():
    conn = get_connection()
    try:
        cur = conn.cursor(dictionary=True)
        cur.execute(
            "SELECT c.cert_id, c.course_name, c.issue_date FROM credentials cr "
            "JOIN certificates c ON c.cert_id = cr.cert_id "
            "GROUP BY c.cert_id, c.course_name, c.issue_date ORDER BY c.cert_id DESC LIMIT 15"
        )
        rows = cur.fetchall()
    finally:
        conn.close()
    for r in rows:
        r["pill"] = _revocation_pill(r["cert_id"])
    return rows


def _revoke_page(form, headline=None, message=None, css="warn"):
    try:
        recent = _recent_signed()
    except Exception:
        recent = []
    return page("Revoke", REVOKE_TPL, form=form, recent=recent, headline=headline, message=message, css=css)


@app.route("/issuer/revoke", methods=["GET", "POST"])
def revoke():
    if request.method == "GET":
        return _revoke_page({})

    form = request.form
    raw_id, reason = form.get("cert_id", "").strip(), form.get("reason", "").strip()
    if not raw_id or not reason:
        return _revoke_page(form, "Missing fields", "Certificate ID and reason are both required.", "warn")
    try:
        cert_id = int(raw_id)
    except ValueError:
        return _revoke_page(form, "Invalid ID", "Certificate ID must be a number.", "warn")

    try:
        conn = get_connection()
        try:
            cur = conn.cursor()
            cur.execute("SELECT cert_id, institution_id FROM certificates WHERE cert_id = %s", (cert_id,))
            exists = cur.fetchone()
        finally:
            conn.close()
        if not exists:
            return _revoke_page(form, "Not found", "No certificate with ID {}.".format(cert_id), "warn")
        if revoke_certificate.is_revoked(cert_id):
            return _revoke_page(form, "Already revoked", "Certificate {} is already revoked.".format(cert_id), "warn")
        revoke_certificate.revoke_certificate(cert_id, reason)
    except Exception as exc:
        return _revoke_page(form, "Revocation failed", str(exc), "invalid")

    published = True
    try:
        publisher.publish_revocation_snapshot(int(exists[1]))
    except Exception:
        published = False
    note = ("A new signed revocation list was published. Verifiers see this revocation once they download "
            "the latest list (Verifier page, \"Download latest revocation list\")."
            if published else "WARNING: the signed revocation list could not be republished.")
    return _revoke_page({}, "Certificate {} revoked".format(cert_id),
                        "Reason recorded privately: {}. The public list shows only the certificate ID and date. {}".format(reason, note),
                        "revoked")


# --------------------------------------------------------------------------
# 3. Holder wallet
# --------------------------------------------------------------------------

HOLDER_TPL = """
<h1>Holder wallet</h1>
<p class="sub">Find your credentials by roll number.</p>
<div class="card">
  <form method="get" action="/holder/lookup">
    <label>Roll number</label>
    <input name="roll" value="{{ roll or '' }}" required>
    <button type="submit">Show my credentials</button>
  </form>
</div>
{% if error %}<div class="banner warn"><b>Notice</b>{{ error }}</div>{% endif %}
{% if certs is not none %}
<div class="card">
  <b>Credentials for {{ roll }}</b>
  {% for c in certs %}
  <hr>
  <p><b>{{ c.course_name }}</b> <span class="muted">(certificate #{{ c.cert_id }}, issued {{ c.issue_date }})</span>
     <span class="pill {{ c.pill }}">{{ 'REVOKED' if c.pill == 'bad' else ('active' if c.pill == 'ok' else '?') }}</span></p>
  {% if c.signed and c.has_file %}
    <p><a class="btn" href="/credentials/credential_{{ c.cert_id }}.json">Download full credential (private)</a>
       {% if c.has_proof %}<a class="btn" href="/credentials/presentation_{{ c.cert_id }}.json">Download shareable proof</a>{% endif %}</p>
    {% if c.has_proof %}
      <p class="muted">Share the proof, not the full credential: it reveals only the course and issue date.</p>
      {% if c.has_qr %}<img class="qr" src="/credentials/presentation_{{ c.cert_id }}_qr.png" alt="QR code">{% endif %}
    {% else %}
      <p class="muted">Older credential format: re-issue it to enable minimal shareable proofs.</p>
    {% endif %}
  {% elif c.signed %}
    <p class="muted">Signed, but the credential file is not on this server.</p>
  {% else %}
    <p class="muted">Not yet signed by the institution.</p>
  {% endif %}
  {% else %}
  <p class="muted">No certificates found for this roll number.</p>
  {% endfor %}
</div>
{% endif %}
"""


@app.route("/holder")
def holder_index():
    return page("Holder", HOLDER_TPL, roll=None, certs=None, error=None)


@app.route("/holder/lookup")
def holder_lookup():
    roll = request.args.get("roll", "").strip()
    if not roll:
        return redirect("/holder")
    return redirect("/holder/{}".format(roll))


@app.route("/holder/<roll_number>")
def holder(roll_number):
    roll_number = roll_number.strip()
    try:
        conn = get_connection()
        try:
            cur = conn.cursor(dictionary=True)
            cur.execute("SELECT * FROM students LIMIT 1")
            sample = cur.fetchall()
            roll_col = _pick(_columns(sample), "roll")
            if roll_col is None:
                return page("Holder", HOLDER_TPL, roll=roll_number, certs=None,
                            error="The students table has no roll-number column.")
            cur.execute(
                "SELECT c.cert_id, c.course_name, c.issue_date, COUNT(cr.credential_id) AS signed "
                "FROM students s JOIN certificates c ON c.student_id = s.student_id "
                "LEFT JOIN credentials cr ON cr.cert_id = c.cert_id "
                "WHERE s.`{}` = %s GROUP BY c.cert_id, c.course_name, c.issue_date "
                "ORDER BY c.cert_id DESC".format(roll_col),
                (roll_number,),
            )
            certs = cur.fetchall()
        finally:
            conn.close()
    except Exception as exc:
        return page("Holder", HOLDER_TPL, roll=roll_number, certs=None, error="Database error: {}".format(exc))

    for c in certs:
        c["signed"] = bool(c["signed"])
        c["has_file"] = os.path.exists(_cred_path(c["cert_id"]))
        c["has_proof"] = c["has_file"] and _ensure_presentation(c["cert_id"])
        c["has_qr"] = c["has_proof"] and os.path.exists(_pres_qr_path(c["cert_id"]))
        c["pill"] = _revocation_pill(c["cert_id"])
    return page("Holder", HOLDER_TPL, roll=roll_number, certs=certs, error=None)


@app.route("/credentials/<path:filename>")
def download_credential(filename):
    # Only serve files that match the exact names we generate.
    if not re.fullmatch(r"(credential|presentation)_\d+(\.json|_qr\.png)", filename):
        abort(404)
    return send_from_directory(CRED_DIR, filename, as_attachment=filename.endswith(".json"))


# --------------------------------------------------------------------------
# 4. Verifier (digital credentials) - NO database access anywhere in this section
# --------------------------------------------------------------------------

VERIFIER_TPL = """
<h1>Verifier</h1>
<p class="sub">Verifies a credential locally using the institution's pinned public key and its signed revocation list.
No database and no per-certificate lookup.</p>

{% if notices %}
<div class="card"><b>Revocation list download</b>
  <table>{% for n in notices %}<tr><td>{{ n.file or '' }}</td><td><span class="pill {{ 'ok' if n.status == 'updated' else 'bad' }}">{{ n.status }}</span></td><td>{{ n.message }}</td></tr>{% endfor %}</table>
</div>
{% endif %}

{% if result %}
<div class="banner {{ result.css }}"><b>{{ result.headline }}</b>{{ result.detail }}</div>
{% if result.fields %}
<div class="card">
  <b>Verified details</b>
  <p class="muted">Only the minimum needed to establish authenticity is shown.</p>
  <table>{% for k, v in result.fields %}<tr><th style="width:35%">{{ k }}</th><td>{{ v }}</td></tr>{% endfor %}</table>
  {% if result.extra %}<p class="muted">This file also contains {{ result.extra }} additional personal field(s) that are not displayed.
     For privacy the holder should share the minimal proof instead of the full credential.</p>{% endif %}
</div>
{% endif %}
{% endif %}

<div class="card">
<form method="post" enctype="multipart/form-data">
  <label>Credential or shareable proof (JSON)</label>
  <input type="file" name="credential" accept=".json,application/json" required>
  <button type="submit">Verify</button>
</form>
</div>

<div class="card">
  <b>What this verifier trusts (local files)</b>
  {% if trust_rows %}
  <table>
    <tr><th>Institution</th><th>Pinned key fingerprint</th><th>Revocation list</th></tr>
    {% for r in trust_rows %}
    <tr><td>{{ r.name }}</td><td class="muted" style="font-family:monospace">{{ r.key_id[:16] }}...</td>
      <td>{% if r.snapshot.authentic %}
            <span class="pill {{ 'ok' if r.snapshot.fresh else 'bad' }}">{{ 'FRESH' if r.snapshot.fresh else 'EXPIRED' }}</span>
            issued {{ r.snapshot.issued_at }}, valid until {{ r.snapshot.valid_until }}
          {% else %}<span class="pill bad">UNAVAILABLE</span> {{ r.snapshot.error }}{% endif %}</td></tr>
    {% endfor %}
  </table>
  {% else %}
  <p class="muted">No institution key is trusted yet. One-time setup: run <code>python publisher.py --trust --sync</code></p>
  {% endif %}
  <form method="post" action="/verifier/refresh"><button type="submit">Download latest revocation list</button></form>
  <p class="muted">A result is only as current as the revocation list above. An expired list is never reported as a clean pass.</p>
</div>
"""


def _verify_result(css, headline, detail, fields=None, extra=0):
    return {"css": css, "headline": headline, "detail": detail, "fields": fields, "extra": extra}


def _verifier_page(result=None, notices=None):
    try:
        rows = trust_store.trust_summary()
    except Exception:
        rows = []
    return page("Verifier", VERIFIER_TPL, result=result, notices=notices, trust_rows=rows)


@app.route("/verifier/refresh", methods=["POST"])
def verifier_refresh():
    return _verifier_page(notices=trust_store.refresh_from_published())


@app.route("/published/<path:filename>")
def published_file(filename):
    """The institution's publication point: the same files a verifier would fetch over HTTP."""
    if not re.fullmatch(r"(institution_\d+_keyinfo|revocations_\d+)\.json", filename):
        abort(404)
    return send_from_directory(trust_store.PUBLISHED_DIR, filename)


@app.route("/verifier", methods=["GET", "POST"])
def verifier():
    if request.method == "GET":
        return _verifier_page()

    upload = request.files.get("credential")
    if upload is None or not upload.filename:
        return _verifier_page(_verify_result("warn", "No file", "Please choose a credential JSON file."))

    raw = upload.read()
    try:
        package = json.loads(raw.decode("utf-8"))
        package["certificate"]["cert_id"], package["signature"], package["institution_id"]  # presence check
    except Exception:
        return _verifier_page(_verify_result(
            "warn", "Not a credential file", "That file is not valid JSON, or is missing certificate, "
            "signature or institution fields."))

    tmp_path = os.path.join(UPLOAD_DIR, "upload_{}.json".format(uuid.uuid4().hex))
    with open(tmp_path, "wb") as fh:
        fh.write(raw)
    try:
        res = verify_module.verify_credential(tmp_path)
    except Exception as exc:
        return _verifier_page(_verify_result(
            "warn", "Verification error", "Could not complete verification: {}".format(exc)))
    finally:
        try:
            os.remove(tmp_path)
        except OSError:
            pass

    status = str(res).lower()
    # Minimum disclosure: never show grade, student id or name, even if the file contains them.
    fields = [("Certificate ID", res.cert_id), ("Issuing institution", res.institution_name or "")]
    for label, key in (("Course", "course_name"), ("Issue date", "issue_date")):
        value = res.disclosed.get(key)
        fields.append((label, str(value)[:10] if (key == "issue_date" and value) else (value or "not disclosed")))
    extra = len(res.extra_fields or [])
    detail = res.detail or ""

    if status == "valid":
        result = _verify_result("valid", "VALID", detail, fields, extra)
    elif status == "revoked":
        when = res.revoked_at
        if when:
            detail += " Revoked on: {}.".format(when)
        result = _verify_result("revoked", "REVOKED", detail, fields, extra)
    elif status == "revocation_unconfirmed":
        result = _verify_result("warn", "SIGNATURE GENUINE - REVOCATION NOT CONFIRMED", detail, fields, extra)
    elif status == "invalid":
        result = _verify_result("invalid", "INVALID", detail or "The signature does not match. "
                                "This credential was tampered with or forged.")
    elif status == "untrusted_key":
        result = _verify_result("invalid", "UNTRUSTED KEY", detail)
    elif status == "unknown_institution":
        result = _verify_result("warn", "UNKNOWN INSTITUTION", detail + " Pin the institution's key first "
                                "(python publisher.py --trust).")
    else:
        result = _verify_result("warn", "Unexpected result", "Verifier returned: {}".format(status))
    return _verifier_page(result)


# --------------------------------------------------------------------------
# 5. Legacy (paper) certificate check
# --------------------------------------------------------------------------

LEGACY_TPL = """
<h1>Legacy certificate check</h1>
<p class="sub">Take a photo of (or upload a scan of) a paper certificate. It is read with OCR and matched against the institution's own records.</p>

{% if result %}
<div class="banner {{ result.css }}"><b>{{ result.headline }}</b>{{ result.detail }}</div>
{% if result.extracted %}
<div class="card">
  <b>Text read from the image</b>
  <table>{% for k, v in result.extracted %}<tr><th style="width:35%">{{ k }}</th><td>{{ v }}</td></tr>{% endfor %}</table>
  <p class="muted">The institution's stored record is compared on the server and is not displayed.</p>
</div>
{% endif %}
{% endif %}

<div class="card">
<form method="post" enctype="multipart/form-data" id="legacyForm">
  <label>Institution</label>
  <select name="institution_id" required>
    {% for i in institutions %}<option value="{{ i.id }}" {% if selected == i.id|string %}selected{% endif %}>{{ i.label }}</option>{% endfor %}
  </select>

  <label>Certificate photo or scan</label>
  <input type="file" name="image" id="imgInput" accept="image/*" required>
  <input type="file" id="phoneCam" accept="image/*" capture="environment" style="display:none">

  <div style="display:flex; gap:10px; flex-wrap:wrap;">
    <button type="button" id="phoneBtn">Take photo (phone camera)</button>
    <button type="button" id="webcamBtn">Use webcam (laptop)</button>
  </div>
  <p class="muted">Tip: lay the certificate flat, good light, fill the frame, avoid glare and shadows.</p>

  <div id="camBox" style="display:none; margin-top:10px;">
    <video id="camVideo" autoplay playsinline style="width:100%; max-width:480px; border-radius:6px; background:#000;"></video><br>
    <button type="button" id="snapBtn">Capture</button>
    <button type="button" id="stopBtn" class="danger">Cancel</button>
  </div>
  <canvas id="camCanvas" style="display:none"></canvas>

  <div id="previewBox" style="display:none; margin-top:12px;">
    <p class="muted" style="margin-bottom:4px;">Selected image:</p>
    <img id="preview" alt="preview" style="max-width:100%; max-height:320px; border:1px solid #e3e6ee; border-radius:6px;">
  </div>

  <button type="submit">Check certificate</button>
</form>
</div>

<script>
(function () {
  var input = document.getElementById('imgInput');
  var phoneCam = document.getElementById('phoneCam');
  var camBox = document.getElementById('camBox');
  var video = document.getElementById('camVideo');
  var canvas = document.getElementById('camCanvas');
  var previewBox = document.getElementById('previewBox');
  var preview = document.getElementById('preview');
  var stream = null;

  function showPreview() {
    if (input.files && input.files[0]) {
      preview.src = URL.createObjectURL(input.files[0]);
      previewBox.style.display = 'block';
    }
  }
  function stopCam() {
    if (stream) { stream.getTracks().forEach(function (t) { t.stop(); }); stream = null; }
    camBox.style.display = 'none';
  }
  input.addEventListener('change', showPreview);

  // Phone: the capture attribute opens the rear camera directly.
  document.getElementById('phoneBtn').addEventListener('click', function () { phoneCam.click(); });
  phoneCam.addEventListener('change', function () {
    if (phoneCam.files && phoneCam.files[0]) {
      var dt = new DataTransfer(); dt.items.add(phoneCam.files[0]); input.files = dt.files; showPreview();
    }
  });

  // Laptop webcam (works on http://127.0.0.1 and https only).
  document.getElementById('webcamBtn').addEventListener('click', function () {
    if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) {
      alert('Webcam is not available here. Use "Choose file" or the phone camera button instead.'); return;
    }
    navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment', width: { ideal: 1920 } } })
      .then(function (s) { stream = s; video.srcObject = s; camBox.style.display = 'block'; })
      .catch(function () { alert('Could not access the camera. Check browser permission, or use Choose file.'); });
  });
  document.getElementById('snapBtn').addEventListener('click', function () {
    if (!video.videoWidth) { return; }
    canvas.width = video.videoWidth; canvas.height = video.videoHeight;
    canvas.getContext('2d').drawImage(video, 0, 0);
    canvas.toBlob(function (blob) {
      var file = new File([blob], 'webcam_capture.jpg', { type: 'image/jpeg' });
      var dt = new DataTransfer(); dt.items.add(file); input.files = dt.files;
      showPreview(); stopCam();
    }, 'image/jpeg', 0.92);
  });
  document.getElementById('stopBtn').addEventListener('click', stopCam);
})();
</script>
"""


def _legacy_page(result=None, selected=""):
    try:
        _, institutions = _load_choices()
    except Exception:
        institutions = []
    return page("Legacy check", LEGACY_TPL, result=result, institutions=institutions, selected=selected)


@app.route("/verifier/legacy", methods=["GET", "POST"])
def verifier_legacy():
    if request.method == "GET":
        return _legacy_page()

    inst_raw = request.form.get("institution_id", "").strip()
    upload = request.files.get("image")
    sel = inst_raw

    def warn(headline, detail):
        return _legacy_page({"css": "warn", "headline": headline, "detail": detail, "extracted": None}, sel)

    if not inst_raw or upload is None or not upload.filename:
        return warn("Missing input", "Choose an institution and upload an image.")
    try:
        institution_id = int(inst_raw)
    except ValueError:
        return warn("Invalid institution", "Institution must be a number.")

    token = uuid.uuid4().hex
    raw_path = os.path.join(UPLOAD_DIR, "legacy_{}.upload".format(token))
    clean_path = os.path.join(UPLOAD_DIR, "legacy_{}.png".format(token))
    upload.save(raw_path)
    try:
        # Normalise phone/webcam photos: apply EXIF rotation (phones store portrait shots
        # sideways with an orientation tag that Tesseract ignores), flatten to RGB, and cap
        # the size so a 12 MP photo does not make OCR slow.
        try:
            from PIL import Image, ImageOps
            with Image.open(raw_path) as img:
                img = ImageOps.exif_transpose(img).convert("RGB")
                if max(img.size) > MAX_IMAGE_SIDE:
                    img.thumbnail((MAX_IMAGE_SIDE, MAX_IMAGE_SIDE))
                img.save(clean_path, "PNG")
        except Exception:
            return warn("Not an image", "That file could not be opened as an image (PNG, JPG, WEBP or BMP).")

        try:
            res = legacy_check.check_legacy_certificate(clean_path, institution_id)
        except Exception as exc:
            return warn("Check failed", "Could not process the image: {}".format(exc))
    finally:
        for p in (raw_path, clean_path):
            try:
                os.remove(p)
            except OSError:
                pass

    status = str(res.get("status", "")).lower()
    message = res.get("message", "")
    extracted = res.get("extracted") or {}
    extracted_rows = [(k.replace("_", " ").title(), v) for k, v in extracted.items()] or None

    if status == "verified":
        out = {"css": "valid", "headline": "VERIFIED",
               "detail": "The certificate matches the institution's record. {}".format(message)}
    elif status == "forgery_flag":
        out = {"css": "invalid", "headline": "FORGERY FLAG", "detail": message}
    elif status == "unreadable":
        out = {"css": "warn", "headline": "UNREADABLE",
               "detail": "{} Try a clearer, flatter, well-lit image.".format(message)}
    else:
        out = {"css": "warn", "headline": "Unexpected result", "detail": str(res)}
    out["extracted"] = extracted_rows
    return _legacy_page(out, sel)


# --------------------------------------------------------------------------
# Errors and entry point
# --------------------------------------------------------------------------

@app.errorhandler(413)
def too_large(_):
    return page("Too large", "<div class='banner warn'><b>File too large</b>Uploads are limited to 25 MB.</div>"), 413


@app.errorhandler(404)
def not_found(_):
    return page("Not found", "<div class='banner warn'><b>Not found</b>That page or file does not exist.</div>"), 404


if __name__ == "__main__":
    # Port 5050: macOS AirPlay Receiver occupies 5000 on recent macOS versions.
    app.run(host="127.0.0.1", port=5050, debug=False)