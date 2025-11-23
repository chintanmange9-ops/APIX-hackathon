import sqlite3
import os

DB_PATH = #path of the database r"path.db"

os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)

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

cur.execute("""
    CREATE TABLE IF NOT EXISTS consent_requests (
        consent_id TEXT PRIMARY KEY,
        token_id TEXT,
        institution_id TEXT,
        requested_fields TEXT,
        purpose TEXT,
        status TEXT,
        created_at TEXT,
        approved_at TEXT
    )
""")

conn.commit()
conn.close()

print("Database initialized successfully at:", DB_PATH)
