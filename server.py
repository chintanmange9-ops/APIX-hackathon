import base64
import csv
import io
import json
import sqlite3
import time
import uuid
from datetime import date, timedelta, datetime
from flask import Flask, request, jsonify, send_file
from cryptography.hazmat.primitives import serialization, hashes
import traceback
from cryptography.hazmat.primitives.asymmetric import padding
import os

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 32 * 1024 * 1024
DB_PATH = #path of the database r"path.db"
KEYS_DIR = "keys"
PRIVATE_KEY_PATH = os.path.join(KEYS_DIR, "private.pem")
PUBLIC_KEY_PATH = os.path.join(KEYS_DIR, "public.pem")

with open(PRIVATE_KEY_PATH, "rb") as f:
    PRIVATE_KEY = serialization.load_pem_private_key(f.read(), password=None)
with open(PUBLIC_KEY_PATH, "rb") as f:
    PUBLIC_KEY = serialization.load_pem_public_key(f.read())

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS tokens(
            token_id TEXT PRIMARY KEY,
            full_name TEXT,
            dob TEXT,
            gender TEXT,
            aadhaar_masked TEXT,
            pan TEXT,
            ckyc_number TEXT,
            mobile TEXT,
            email TEXT,
            address_line_1 TEXT,
            address_line_2 TEXT,
            city TEXT,
            state TEXT,
            pincode TEXT,
            client_photo TEXT,
            signature_image TEXT,
            issuer_id TEXT,
            issuer_name TEXT,
            token_version TEXT,
            kyc_verified_date TEXT,
            kyc_expires_on TEXT,
            payload TEXT,
            signature TEXT,
            metadata TEXT,
            status TEXT DEFAULT 'active'
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS issuers (
            issuer_id TEXT PRIMARY KEY,
            issuer_name TEXT,
            token_version TEXT,
            kyc_duration_days INTEGER,
            api_key TEXT,
            metadata TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            action TEXT,
            token_id TEXT,
            issuer_id TEXT,
            details TEXT,
            ts TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def get_db_conn():
    return sqlite3.connect(DB_PATH)

def get_token(token_id):
    conn = get_db_conn()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM tokens WHERE token_id=?", (token_id,))
    row = cur.fetchone()
    conn.close()
    return dict(row) if row else None

def audit_log(action, token_id=None, issuer_id=None, details=None):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audit_logs(action, token_id, issuer_id, details, ts) VALUES (?, ?, ?, ?, ?)",
        (action, token_id, issuer_id, json.dumps(details) if details else None, datetime.utcnow().isoformat())
    )
    conn.commit()
    conn.close()

def issuer_get(issuer_id):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT issuer_id, issuer_name, token_version, kyc_duration_days, api_key, metadata FROM issuers WHERE issuer_id=?", (issuer_id,))
    r = cur.fetchone()
    conn.close()
    if not r:
        return None
    return {
        "issuer_id": r[0],
        "issuer_name": r[1],
        "token_version": r[2],
        "kyc_duration_days": r[3],
        "api_key": r[4],
        "metadata": json.loads(r[5]) if r[5] else {}
    }

def canonical_payload_bytes(payload_dict):
    return json.dumps(payload_dict, separators=(",", ":"), sort_keys=True).encode()

@app.route("/issuers", methods=["GET", "POST"])
def issuers_collection():
    if request.method == "GET":
        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("SELECT issuer_id, issuer_name, token_version, kyc_duration_days, api_key, metadata FROM issuers")
        rows = cur.fetchall()
        conn.close()
        out = []
        for r in rows:
            out.append({
                "issuer_id": r[0],
                "issuer_name": r[1],
                "token_version": r[2],
                "kyc_duration_days": r[3],
                "api_key": r[4],
                "metadata": json.loads(r[5]) if r[5] else {}
            })
        return jsonify(out), 200

    data = request.json or {}
    for f in ("issuer_id", "issuer_name"):
        if f not in data or not data[f]:
            return jsonify({"error": f"Missing {f}"}), 400
    issuer_id = data["issuer_id"]
    issuer_name = data["issuer_name"]
    token_version = data.get("token_version", "1.0")
    kyc_days = int(data.get("kyc_duration_days", 365))
    api_key = data.get("api_key", f"KEY_{int(time.time())}")
    metadata = data.get("metadata", {})
    conn = get_db_conn()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO issuers(issuer_id, issuer_name, token_version, kyc_duration_days, api_key, metadata) VALUES (?, ?, ?, ?, ?, ?)",
            (issuer_id, issuer_name, token_version, kyc_days, api_key, json.dumps(metadata))
        )
        conn.commit()
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500
    conn.close()
    return jsonify({"status": "created", "issuer_id": issuer_id, "api_key": api_key}), 201

@app.route("/issuers/<issuer_id>", methods=["GET", "PUT", "DELETE"])
def issuer_item(issuer_id):
    conn = get_db_conn()
    cur = conn.cursor()
    if request.method == "GET":
        cur.execute("SELECT issuer_id, issuer_name, token_version, kyc_duration_days, api_key, metadata FROM issuers WHERE issuer_id=?", (issuer_id,))
        r = cur.fetchone()
        conn.close()
        if not r:
            return jsonify({"error": "Issuer not found"}), 404
        return jsonify({
            "issuer_id": r[0],
            "issuer_name": r[1],
            "token_version": r[2],
            "kyc_duration_days": r[3],
            "api_key": r[4],
            "metadata": json.loads(r[5]) if r[5] else {}
        }), 200

    if request.method == "PUT":
        data = request.json or {}
        fields = []
        params = []
        if "issuer_name" in data:
            fields.append("issuer_name=?"); params.append(data["issuer_name"])
        if "token_version" in data:
            fields.append("token_version=?"); params.append(data["token_version"])
        if "kyc_duration_days" in data:
            fields.append("kyc_duration_days=?"); params.append(int(data["kyc_duration_days"]))
        if "api_key" in data:
            fields.append("api_key=?"); params.append(data["api_key"])
        if "metadata" in data:
            fields.append("metadata=?"); params.append(json.dumps(data["metadata"]))
        if not fields:
            conn.close()
            return jsonify({"error": "No fields to update"}), 400
        params.append(issuer_id)
        cur.execute(f"UPDATE issuers SET {','.join(fields)} WHERE issuer_id=?", params)
        conn.commit()
        conn.close()
        return jsonify({"status": "updated"}), 200

    cur.execute("DELETE FROM issuers WHERE issuer_id=?", (issuer_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted"}), 200

@app.route("/issue", methods=["POST"])
def issue():
    try:
        data = request.json or {}
        required = ["aadhaar_masked", "full_name", "dob", "issuer_id", "issuer_name", "token_version"]
        for k in required:
            if k not in data or not data[k]:
                return jsonify({"error": f"Missing field: {k}"}), 400

        try:
            date.fromisoformat(data["dob"])
        except Exception:
            return jsonify({"error": "Invalid DOB format (YYYY-MM-DD)"}), 400

        today = date.today()
        issuer = issuer_get(data.get("issuer_id"))
        if issuer:
            duration = int(issuer.get("kyc_duration_days", 365))
        else:
            duration = int(data.get("kyc_duration_days", 365))
        expires = today + timedelta(days=duration)

        payload = {
            "full_name": data.get("full_name"),
            "dob": data.get("dob"),
            "gender": data.get("gender", ""),
            "aadhaar_masked": data.get("aadhaar_masked"),
            "pan": data.get("pan", ""),
            "ckyc_number": data.get("ckyc_number", ""),
            "mobile": data.get("mobile", ""),
            "email": data.get("email", ""),
            "address_line_1": data.get("address_line_1", ""),
            "address_line_2": data.get("address_line_2", ""),
            "city": data.get("city", ""),
            "state": data.get("state", ""),
            "pincode": data.get("pincode", ""),
            "client_photo": data.get("client_photo", ""),
            "signature_image": data.get("signature_image", ""),
            "issuer_id": data.get("issuer_id"),
            "issuer_name": data.get("issuer_name"),
            "token_version": data.get("token_version"),
            "kyc_verified_date": today.isoformat(),
            "kyc_expires_on": expires.isoformat()
        }

        pb = canonical_payload_bytes(payload)
        pb64 = base64.b64encode(pb).decode()
        sig = PRIVATE_KEY.sign(pb, padding.PKCS1v15(), hashes.SHA256())
        sig_b64 = base64.b64encode(sig).decode()

        token_id = f"TOK{int(time.time())}"

        conn = get_db_conn()
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO tokens(
                token_id, full_name, dob, gender, aadhaar_masked, pan, ckyc_number,
                mobile, email, address_line_1, address_line_2, city, state, pincode,
                client_photo, signature_image, issuer_id, issuer_name, token_version,
                kyc_verified_date, kyc_expires_on, payload, signature, metadata, status
            ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
        """, (
            token_id, payload["full_name"], payload["dob"], payload["gender"], payload["aadhaar_masked"],
            payload["pan"], payload["ckyc_number"], payload["mobile"], payload["email"],
            payload["address_line_1"], payload["address_line_2"], payload["city"], payload["state"],
            payload["pincode"], payload["client_photo"], payload["signature_image"], payload["issuer_id"],
            payload["issuer_name"], payload["token_version"], payload["kyc_verified_date"],
            payload["kyc_expires_on"], pb64, sig_b64, json.dumps({"issued_ts": int(time.time())}), "active"
        ))
        conn.commit()
        conn.close()

        audit_log("issue", token_id=token_id, issuer_id=payload["issuer_id"], details={"issued_ts": int(time.time())})

        return jsonify({
            "status": "issued",
            "token_id": token_id,
            "qr_lookup_url": f"{request.host_url.rstrip('/')}/lookup/{token_id}",
            "signature": sig_b64
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/lookup/<token_id>", methods=["GET"])
def lookup(token_id):
    token = get_token(token_id)
    if not token:
        return jsonify({"error": "Token not found"}), 404

    try:
        decoded = json.loads(base64.b64decode(token["payload"]))
    except:
        decoded = {}

    try:
        expires = datetime.fromisoformat(token["kyc_expires_on"])
        expiry_status = "Active" if expires >= datetime.now() else "Expired"
    except:
        expiry_status = "Unknown"

    final_status = token["status"]
    if final_status == "Active":
        final_status = expiry_status

    out = {
        "token_id": token["token_id"],
        "kyc_status": final_status,
        "kyc_verified_date": token["kyc_verified_date"],
        "kyc_expires_on": token["kyc_expires_on"],
        "issuer_id": token["issuer_id"],
        "issuer_name": token["issuer_name"],
        "token_version": token["token_version"],
        "signature": token.get("signature", "")
    }
    out.update(decoded)

    return jsonify(out), 200

@app.route("/verify/<token_id>", methods=["GET"])
def verify_endpoint(token_id):
    token = get_token(token_id)
    if not token:
        audit_log("verify_miss", token_id=token_id)
        return jsonify({"is_valid": False, "reason": "Token not found"}), 404

    try:
        pb64 = token.get("payload", "")
        pb = base64.b64decode(pb64)
        decoded = json.loads(pb.decode())
    except Exception:
        audit_log("verify_fail_payload", token_id=token_id)
        return jsonify({"is_valid": False, "reason": "Malformed payload"}), 400

    if token.get("status") == "revoked":
        audit_log("verify_revoked", token_id=token_id)
        return jsonify({"is_valid": False, "reason": "Token revoked"}), 200

    try:
        expiry = datetime.fromisoformat(token["kyc_expires_on"])
        if expiry < datetime.now():
            audit_log("verify_expired", token_id=token_id)
            return jsonify({"is_valid": False, "reason": f"Token expired on {token['kyc_expires_on']}", "token_id": token["token_id"]}), 200
    except Exception:
        audit_log("verify_fail_expiry", token_id=token_id)
        return jsonify({"is_valid": False, "reason": "Invalid expiry format"}), 400

    sig_b64 = token.get("signature", "")
    try:
        sig = base64.b64decode(sig_b64)
        PUBLIC_KEY.verify(sig, pb, padding.PKCS1v15(), hashes.SHA256())
        sig_ok = True
    except Exception:
        sig_ok = False

    if not sig_ok:
        audit_log("verify_sig_fail", token_id=token_id)
        return jsonify({"is_valid": False, "reason": "Signature verification failed", "token_id": token["token_id"]}), 200

    resp = {
        "is_valid": True,
        "reason": "Token is valid and active",
        "verified_on": datetime.now().isoformat(),
        "token_id": token["token_id"],
        "issuer_name": token["issuer_name"],
        "token_version": token["token_version"],
        "kyc_expires_on": token["kyc_expires_on"]
    }

    for k in ("kyc_expires_on", "issuer_name", "token_version"):
        decoded.pop(k, None)

    resp.update(decoded)
    audit_log("verify", token_id=token_id, issuer_id=token.get("issuer_id"))
    return jsonify(resp), 200

@app.route("/renew/<token_id>", methods=["POST"])
def renew(token_id):
    token = get_token(token_id)
    if not token:
        return jsonify({"error": "Token not found"}), 404
    issuer = issuer_get(token.get("issuer_id"))
    duration = issuer.get("kyc_duration_days", 365) if issuer else 365
    new_expiry = (datetime.now() + timedelta(days=int(duration))).isoformat()
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("UPDATE tokens SET kyc_expires_on=?, status=? WHERE token_id=?", (new_expiry, "active", token_id))
    conn.commit()
    conn.close()
    audit_log("renew", token_id=token_id, issuer_id=token.get("issuer_id"), details={"new_expiry": new_expiry})
    return jsonify({"status": "renewed", "new_expiry": new_expiry}), 200

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route("/revoke/<token_id>", methods=["POST"])
def revoke(token_id):
    conn = get_db()
    cur = conn.cursor()

    cur.execute("UPDATE tokens SET status=? WHERE token_id=?", ("Revoked", token_id))
    conn.commit()

    if cur.rowcount == 0:
        audit_log("revoke_failed", token_id=token_id)
        return jsonify({"error": "Token not found"}), 404

    audit_log("revoke_success", token_id=token_id)
    return jsonify({"success": True, "message": "Token revoked"}), 200

@app.route("/audit/<token_id>", methods=["GET"])
def get_audit(token_id):
    conn = get_db_conn()
    cur = conn.cursor()
    cur.execute("SELECT id, action, token_id, issuer_id, details, ts FROM audit_logs WHERE token_id=? ORDER BY id DESC", (token_id,))
    rows = cur.fetchall()
    conn.close()
    out = []
    for r in rows:
        out.append({
            "id": r[0],
            "action": r[1],
            "token_id": r[2],
            "issuer_id": r[3],
            "details": json.loads(r[4]) if r[4] else None,
            "ts": r[5]
        })
    return jsonify(out), 200

def tokens_to_csv_bytes(tokens):
    headers = ["token_id", "full_name", "aadhaar_masked", "dob", "city", "state", "pincode",
               "mobile", "email", "issuer_id", "issuer_name", "token_version", "kyc_verified_date", "kyc_expires_on", "status"]
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=headers)
    writer.writeheader()
    for t in tokens:
        row = {k: t.get(k, "") for k in headers}
        writer.writerow(row)
    return out.getvalue().encode("utf-8")

@app.route("/download/token/<token_id>", methods=["GET"])
def download_token_csv(token_id):
    token = get_token(token_id)
    if not token:
        return jsonify({"error": "Token not found"}), 404
    try:
        pb = base64.b64decode(token.get("payload", ""))
        decoded = json.loads(pb.decode())
    except Exception:
        decoded = {}
        clean = {
            "token_id": token.get("token_id"),
            "full_name": decoded.get("full_name", ""),
            "aadhaar_masked": decoded.get("aadhaar_masked", ""),
            "dob": decoded.get("dob", ""),
            "city": decoded.get("city", ""),
            "state": decoded.get("state", ""),
            "pincode": decoded.get("pincode", ""),
            "mobile": decoded.get("mobile", ""),
            "email": decoded.get("email", ""),
            "issuer_id": token.get("issuer_id"),
            "issuer_name": token.get("issuer_name"),
            "token_version": token.get("token_version"),
            "kyc_verified_date": token.get("kyc_verified_date"),
            "kyc_expires_on": token.get("kyc_expires_on"),
            "status": token.get("status"),
        }
        csv_bytes = tokens_to_csv_bytes([clean])

    audit_log("download_token", token_id=token_id, issuer_id=token.get("issuer_id"))
    return send_file(io.BytesIO(csv_bytes), mimetype="text/csv", as_attachment=True, download_name=f"{token_id}.csv")

@app.route("/download/all", methods=["GET"])
def download_all_csv():
    issuer_filter = request.args.get("issuer_id")
    conn = get_db_conn()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    if issuer_filter:
        cur.execute("SELECT * FROM tokens WHERE issuer_id=?", (issuer_filter,))
    else:
        cur.execute("SELECT * FROM tokens")
    rows = cur.fetchall()
    conn.close()
    tokens = []
    for r in rows:
        token = dict(r)
        try:
            pb = base64.b64decode(token.get("payload", ""))
            decoded = json.loads(pb.decode())
        except Exception:
            decoded = {}
        clean = {
            "token_id": token.get("token_id"),
            "full_name": decoded.get("full_name", ""),
            "aadhaar_masked": decoded.get("aadhaar_masked", ""),
            "dob": decoded.get("dob", ""),
            "city": decoded.get("city", ""),
            "state": decoded.get("state", ""),
            "pincode": decoded.get("pincode", ""),
            "mobile": decoded.get("mobile", ""),
            "email": decoded.get("email", ""),
            "issuer_id": token.get("issuer_id"),
            "issuer_name": token.get("issuer_name"),
            "token_version": token.get("token_version"),
            "kyc_verified_date": token.get("kyc_verified_date"),
            "kyc_expires_on": token.get("kyc_expires_on"),
            "status": token.get("status"),
        }
        tokens.append(clean)

    csv_bytes = tokens_to_csv_bytes(tokens)
    audit_log("download_all", details={"issuer_filter": issuer_filter})
    return send_file(io.BytesIO(csv_bytes), mimetype="text/csv", as_attachment=True, download_name="all_tokens.csv")

@app.route("/")
def root():
    return jsonify({"status": "running", "message": "Tokenised KYC API active"}), 200


@app.route("/consent/request", methods=["POST"])
def request_consent():
    try:
        print("RAW REQUEST:", request.data)

        data = request.get_json(force=True)
        print("PARSED JSON:", data, type(data))

        if isinstance(data, list):
            data = data[0]

        consent_id = str(uuid.uuid4())
        created_at = datetime.now().isoformat()

        conn = get_db_conn()
        cur = conn.cursor()

        cur.execute("""
            INSERT INTO consent_requests (
                consent_id, token_id, institution_id,
                requested_fields, purpose, status, created_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            consent_id,
            data.get("token_id"),
            data.get("institution_id"),
            ",".join(data.get("requested_fields", [])),
            data.get("purpose"),
            "pending",
            created_at
        ))

        conn.commit()
        conn.close()

        return jsonify({"status": "success", "consent_id": consent_id})

    except Exception as e:
        print("ERROR:", str(e))
        traceback.print_exc()
        return jsonify({"error": "Internal Server Error"}), 500



@app.route("/consent/approve", methods=["POST"])
def approve_consent():
    data = request.json
    approved_at = datetime.now().isoformat()

    conn = get_db_conn()
    cur = conn.cursor()

    cur.execute("""
        UPDATE consent_requests
        SET status='approved', approved_at=?
        WHERE consent_id=?
    """, (approved_at, data["consent_id"]))

    conn.commit()
    conn.close()

    return jsonify({"status": "approved"})

@app.route("/consent/all", methods=["GET"])
def get_all_consent():
    conn = get_db_conn()
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()

    cur.execute("SELECT * FROM consent_requests ORDER BY created_at DESC")
    rows = cur.fetchall()
    conn.close()

    data = []
    for r in rows:
        data.append({k: r[k] for k in r.keys()})

    return jsonify({"consents": data})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
