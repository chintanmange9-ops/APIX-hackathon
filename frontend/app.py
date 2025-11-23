import streamlit as st
import requests
import json
import base64
from io import BytesIO
from PIL import Image
import qrcode
import sqlite3
import pandas as pd
from datetime import date, timedelta, datetime
import re

city_filter = ""
state_filter = ""
issuer_filter = ""
status_filter = "All"

def compute_status(r):
    if str(r.get("status", "")).lower() == "revoked":
        return "Revoked"
    try:
        return "Active" if pd.to_datetime(r.get("kyc_expires_on", pd.Timestamp.min)) >= pd.Timestamp.now() else "Expired"
    except Exception:
        return "Invalid"


DB_PATH = #path of the database r"path.db"
SERVER_IP = "10.26.85.117"    #ip address on which server is running can found using ipconfig on cmd
BASE_URL = f"http://{SERVER_IP}:5000"

st.set_page_config(page_title="Tokenised KYC Demo", layout="centered")
st.title("Tokenised KYC Prototype")

if "single_token_excel" not in st.session_state:
    st.session_state.single_token_excel = None
if "all_tokens_excel" not in st.session_state:
    st.session_state.all_tokens_excel = None
if "fetched_token" not in st.session_state:
    st.session_state.fetched_token = None
if "issuers_cache" not in st.session_state:
    st.session_state.issuers_cache = []
if "active_issuer" not in st.session_state:
    st.session_state.active_issuer = None

def generate_qr(url: str):
    qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_L, box_size=8, border=4)
    qr.add_data(url)
    qr.make(fit=True)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()

def csv_to_excel_bytes(csv_bytes):
    try:
        df = pd.read_csv(BytesIO(csv_bytes))
    except Exception:
        df = pd.read_csv(BytesIO(csv_bytes), encoding="latin1")
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Tokens")
    return output.getvalue()

def df_to_excel_bytes(df: pd.DataFrame):
    output = BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Tokens")
    return output.getvalue()

def decode_payload(df):
    decoded_rows = []
    for _, row in df.iterrows():
        payload_b64 = row.get("payload", "")
        decoded = {}
        if payload_b64:
            try:
                decoded = json.loads(base64.b64decode(payload_b64).decode())
            except Exception:
                decoded = {}
        merged_row = {**decoded, **row.to_dict()}
        merged_row.pop("payload", None)
        decoded_rows.append(merged_row)
    df_decoded = pd.DataFrame(decoded_rows)
    relevant_cols = [
        "token_id", "full_name", "dob", "gender", "aadhaar_masked", "pan", "ckyc_number",
        "mobile", "email", "city", "state", "pincode", "issuer_id", "issuer_name",
        "token_version", "kyc_duration_days", "kyc_verified_date", "kyc_expires_on",
        "client_photo", "signature_image", "status"
    ]
    cols = [c for c in relevant_cols if c in df_decoded.columns]
    return df_decoded[cols]

tabs = st.tabs(["Issuer Management", "Issue Token", "Lookup & Verify", "DB Viewer", "Consent Management", "Audit Logs"])

with tabs[0]:
    st.header("Issuer Management")

    if "issuers_cache" not in st.session_state:
        st.session_state.issuers_cache = []

    try:
        r = requests.get(f"{BASE_URL}/issuers", timeout=5)
        if r.status_code == 200:
            st.session_state.issuers_cache = r.json() or []
    except Exception:
        st.session_state.issuers_cache = []

    issuers = st.session_state.issuers_cache
    issuer_ids = [i["issuer_id"] for i in issuers] or ["BANK001"]
    issuer_map = {i["issuer_id"]: i for i in issuers}

    col1, col2 = st.columns([3, 1])
    with col1:
        selected_issuer = st.selectbox("Select active issuer", options=issuer_ids, index=0)
    with col2:
        if st.button("Refresh Issuers"):
            try:
                r = requests.get(f"{BASE_URL}/issuers", timeout=5)
                if r.status_code == 200:
                    st.session_state.issuers_cache = r.json() or []
                    st.rerun()
            except Exception:
                st.warning("Failed to refresh issuers")

    st.session_state.active_issuer = selected_issuer
    st.write("Active issuer:", st.session_state.get("active_issuer"))

    st.subheader("Create new issuer")
    new_id = st.text_input("Issuer ID (unique)", key="new_issuer_id")
    new_name = st.text_input("Issuer Name", key="new_issuer_name")
    new_version = st.text_input("Token Version", value="1.0", key="new_token_version")
    new_duration = st.number_input("KYC Duration (days)", min_value=1, value=365, key="new_kyc_days")

    if st.button("Create Issuer"):
        if not new_id.strip() or not new_name.strip() or not new_version.strip():
            st.error("Issuer ID, Name, and Version cannot be blank")
        elif new_id.strip() in issuer_ids:
            st.error("Issuer ID already exists")
        else:
            payload = {
                "issuer_id": new_id.strip(),
                "issuer_name": new_name.strip(),
                "token_version": new_version.strip(),
                "kyc_duration_days": int(new_duration)
            }
            try:
                r = requests.post(f"{BASE_URL}/issuers", json=payload, timeout=10)
                if r.status_code in (200, 201):
                    try:
                        rr = requests.get(f"{BASE_URL}/issuers", timeout=5)
                        if rr.status_code == 200:
                            st.session_state.issuers_cache = rr.json() or []
                    except Exception:
                        pass
                    st.rerun()
                else:
                    st.error(f"Create failed: {r.status_code} {r.text}")
            except Exception as e:
                st.error(f"Request failed: {e}")

    st.subheader("Existing issuers")
    if issuers:
        for it in issuers:
            st.markdown(f"---\n**{it['issuer_id']}** — {it['issuer_name']} "
                        f"(v{it.get('token_version', '1.0')}) — KYC days: {it.get('kyc_duration_days', 365)}")
            
            col1, col2, col3 = st.columns([2,2,1])
            
            with col1:
                if st.button(f"Edit {it['issuer_id']}", key=f"edit_{it['issuer_id']}"):
                    st.session_state.editing_issuer = it['issuer_id']
                    st.rerun()
            with col2:
                if st.button(f"Delete {it['issuer_id']}", key=f"delete_{it['issuer_id']}"):
                    try:
                        rr = requests.delete(f"{BASE_URL}/issuers/{it['issuer_id']}", timeout=5)
                        if rr.status_code == 200:
                            st.success(f"Issuer {it['issuer_id']} deleted")
                            st.rerun()
                        else:
                            st.error(f"Delete failed: {rr.status_code}")
                    except Exception as e:
                        st.error(f"Delete request failed: {e}")
            with col3:
                st.text(f"KYC days: {it.get('kyc_duration_days', 365)}")
        
        if "editing_issuer" in st.session_state and st.session_state.editing_issuer:
            edit_id = st.session_state.editing_issuer
            issuer_to_edit = issuer_map.get(edit_id)
            if issuer_to_edit:
                st.subheader(f"Edit Issuer: {edit_id}")
                edit_name = st.text_input("Issuer Name", value=issuer_to_edit.get("issuer_name", ""), key="edit_name")
                edit_version = st.text_input("Token Version", value=issuer_to_edit.get("token_version", "1.0"), key="edit_version")
                edit_duration = st.number_input("KYC Duration (days)", min_value=1,
                                                value=int(issuer_to_edit.get("kyc_duration_days", 365)),
                                                key="edit_duration")
                if st.button("Update Issuer"):
                    payload = {
                        "issuer_name": edit_name.strip(),
                        "token_version": edit_version.strip(),
                        "kyc_duration_days": int(edit_duration)
                    }
                    try:
                        rr = requests.put(f"{BASE_URL}/issuers/{edit_id}", json=payload, timeout=10)
                        if rr.status_code == 200:
                            st.success("Issuer updated")
                            st.session_state.editing_issuer = None
                            st.rerun()
                        else:
                            st.error(f"Update failed: {rr.status_code}")
                    except Exception as e:
                        st.error(f"Update request failed: {e}")
    else:
        st.info("No issuers available")

with tabs[1]:
    st.header("Issue New Client KYC Token (via backend)")
    full_name = st.text_input("Full Name", key="issue_fullname")
    dob = st.date_input("Date of Birth", key="issue_dob")
    gender = st.text_input("Gender", key="issue_gender")
    aadhaar_masked = st.text_input("Aadhaar Ref (masked)", key="issue_aadhaar")
    pan = st.text_input("PAN", key="issue_pan")
    ckyc_number = st.text_input("CKYC Number", key="issue_ckyc")
    mobile = st.text_input("Mobile Number", key="issue_mobile")
    email = st.text_input("Email", key="issue_email")
    address_line_1 = st.text_input("Address Line 1", key="issue_addr1")
    address_line_2 = st.text_input("Address Line 2", key="issue_addr2")
    city = st.text_input("City", key="issue_city")
    state = st.text_input("State", key="issue_state")
    pincode = st.text_input("Pincode", key="issue_pin")
    uploaded_photo = st.file_uploader("Client Photo", type=["png", "jpg", "jpeg"], key="issue_photo")
    uploaded_signature = st.file_uploader("Signature Image", type=["png", "jpg", "jpeg"], key="issue_sig")

    if st.button("Issue Client Token"):
        if not st.session_state.get("active_issuer"):
            st.error("Select an issuer first in Issuer Management")
        elif not aadhaar_masked.strip() or not full_name.strip() or not dob:
            st.error("Aadhaar, Full Name and DOB are required.")
        elif not re.match(r"^\d{4}-\d{4}-\d{4}$", aadhaar_masked.strip()):
            st.error("Aadhaar must be in XXXX-XXXX-XXXX format")
        elif mobile and not re.match(r"^\d{10}$", mobile.strip()):
            st.error("Mobile must be 10 digits")
        elif pan and not re.match(r"^[A-Z]{5}\d{4}[A-Z]$", pan.strip().upper()):
            st.error("PAN must be in valid format (ABCDE1234F)")
        elif email and not re.match(r"^[^@]+@[^@]+\.[^@]+$", email.strip()):
            st.error("Invalid email format")
        else:
            payload = {
                "full_name": full_name.strip(),
                "dob": dob.isoformat(),
                "gender": gender.strip(),
                "aadhaar_masked": aadhaar_masked.strip(),
                "pan": pan.strip().upper(),
                "ckyc_number": ckyc_number.strip(),
                "mobile": mobile.strip(),
                "email": email.strip(),
                "address_line_1": address_line_1.strip(),
                "address_line_2": address_line_2.strip(),
                "city": city.strip(),
                "state": state.strip(),
                "pincode": pincode.strip(),
                "issuer_id": st.session_state.active_issuer,
                "issuer_name": issuer_map.get(st.session_state.active_issuer, {}).get("issuer_name", ""),
                "token_version": issuer_map.get(st.session_state.active_issuer, {}).get("token_version", "1.0")
            }
            if uploaded_photo:
                uploaded_photo.seek(0)
                payload["client_photo"] = base64.b64encode(uploaded_photo.read()).decode()
            else:
                payload["client_photo"] = ""
            if uploaded_signature:
                uploaded_signature.seek(0)
                payload["signature_image"] = base64.b64encode(uploaded_signature.read()).decode()
            else:
                payload["signature_image"] = ""
            try:
                r = requests.post(f"{BASE_URL}/issue", json=payload, timeout=20)
            except Exception as e:
                st.error(f"Issue request failed: {e}")
                r = None
            if r is None:
                st.warning("No response from server")
            else:
                if r.status_code == 200:
                    jr = r.json()
                    token_id = jr.get("token_id")
                    st.success(f"Issued token: {token_id}")
                    st.write("Lookup URL:", jr.get("qr_lookup_url"))
                    qr_img = generate_qr(jr.get("qr_lookup_url"))
                    st.image(qr_img, caption="Scan to view token")
                else:
                    st.error(f"Issue failed: {r.status_code} {r.text}")

with tabs[2]:
    st.header("Lookup & Verify Token")
    lookup_id = st.text_input("Enter Token ID for Lookup", key="lookup2")
    verifier_last4 = st.text_input("Verifier: Last 4 digits of Aadhaar (optional)", max_chars=4, key="ver_last4")
    verifier_dob = st.date_input("Verifier: DOB (optional)", key="ver_dob")
    if st.button("Lookup Token"):
        st.session_state.fetched_token = None
        if not lookup_id.strip():
            st.error("Enter token id")
        else:
            try:
                resp = requests.get(f"{BASE_URL}/lookup/{lookup_id.strip()}", timeout=10)
            except Exception as e:
                st.error(f"Request failed: {e}")
                resp = None
            if resp is None:
                st.warning("No response")
            else:
                if resp.status_code == 200:
                    token_json = resp.json()
                    st.session_state.fetched_token = token_json
                elif resp.status_code == 404:
                    st.warning("Token not found")
                else:
                    st.error(f"Lookup failed: {resp.status_code} {resp.text}")
    token_json = st.session_state.get("fetched_token")
    if token_json:
        st.markdown(f"**Token ID:** {token_json.get('token_id','')}")
        st.markdown(f"**Name:** {token_json.get('full_name','')}")
        st.markdown(f"**Aadhaar (masked):** {token_json.get('aadhaar_masked','')}")
        st.markdown(f"**DOB:** {token_json.get('dob','')}")
        st.markdown(f"**Issuer:** {token_json.get('issuer_name','')}")
        st.markdown(f"**Expires On:** {token_json.get('kyc_expires_on','')}")
        st.markdown(f"**Status:** {token_json.get('kyc_status','')}")
        for label in ["client_photo", "signature_image"]:
            val = token_json.get(label)
            if val:
                try:
                    img = Image.open(BytesIO(base64.b64decode(val)))
                    st.image(img, caption=label)
                except Exception:
                    st.warning(f"Cannot display {label}")
        try:
            ar = requests.get(f"{BASE_URL}/audit/{token_json.get('token_id')}", timeout=5)
            if ar.status_code == 200:
                st.subheader("Audit Trail")
                logs = ar.json()
                for l in logs:
                    st.text(f"{l.get('ts')} — {l.get('action')} — {l.get('details')}")
        except Exception:
            pass
        if st.button("Verify Locally (last4 Aadhaar or DOB)"):
            verification_ok = False
            reason = ""
            try:
                expires_on = token_json.get("kyc_expires_on")
                if expires_on:
                    expires_dt = datetime.fromisoformat(expires_on)
                    if expires_dt < datetime.now():
                        verification_ok = False
                        reason = f"Expired on {expires_on}"
                    else:
                        if verifier_last4 and verifier_last4.isdigit() and len(verifier_last4) == 4:
                            masked = token_json.get("aadhaar_masked", "")
                            digits = "".join([c for c in masked if c.isdigit()])
                            if digits.endswith(verifier_last4):
                                verification_ok = True
                                reason = "Aadhaar last4 matched and token active"
                            else:
                                verification_ok = False
                                reason = "Aadhaar last4 mismatch"
                        elif verifier_dob:
                            token_dob = token_json.get("dob")
                            try:
                                if token_dob and datetime.fromisoformat(token_dob).date() == verifier_dob:
                                    verification_ok = True
                                    reason = "DOB matched and token active"
                                else:
                                    verification_ok = False
                                    reason = "DOB mismatch"
                            except Exception:
                                verification_ok = False
                                reason = "Invalid DOB in token"
                        else:
                            verification_ok = False
                            reason = "No verifier field provided"
                else:
                    verification_ok = False
                    reason = "No expiry in token"
            except Exception as e:
                verification_ok = False
                reason = f"Verification error: {e}"
            if verification_ok:
                st.success(reason)
            else:
                st.error(reason)
        if st.button("Verify with Server"):
            try:
                vr = requests.get(f"{BASE_URL}/verify/{token_json.get('token_id')}", timeout=10)
            except Exception as e:
                st.error(f"Verify request failed: {e}")
                vr = None
            if vr is None:
                st.warning("No verification response")
            else:
                try:
                    vrj = vr.json()
                except Exception:
                    st.error("Invalid verify response")
                    vrj = {}
                if vr.status_code == 200 and vrj.get("is_valid"):
                    st.success(f"Verified by server: {vrj.get('reason')}")
                else:
                    st.error(f"Server verification: {vrj.get('reason', vr.text)}")
                st.json(vrj)

with tabs[3]:
    st.header("View Tokens in Database")
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    view_option = st.radio("Choose View Option", ["View by Token ID", "View All Tokens"])
    try:
        if view_option == "View by Token ID":
            token_id_input = st.text_input("Enter Token ID", key="view_id2")
            if st.button("Fetch Token", key="fetch_single2"):
                st.session_state.single_token_excel = None
                if token_id_input.strip():
                    df = pd.read_sql_query("SELECT * FROM tokens WHERE token_id=?", conn, params=(token_id_input.strip(),))
                    if not df.empty:
                        df_clean = decode_payload(df)
                        df_clean["aadhaar_masked"] = df_clean["aadhaar_masked"].astype(str)
                        row = df_clean.iloc[0]
                        expired = pd.to_datetime(row.get("kyc_expires_on", "")) < pd.Timestamp.now()
                        display_status = row.get("status", "active")
                        if display_status == "revoked":
                            status_text = "❌ Revoked"
                        else:
                            status_text = "❌ Expired" if expired else "✅ Active"
                        st.markdown(f"**Token ID:** {row.get('token_id', '')}")
                        st.text(f"Name: {row.get('full_name', '')}, Aadhaar: {row.get('aadhaar_masked', '')}, DOB: {row.get('dob', '')}")
                        st.text(f"City: {row.get('city', '')}, State: {row.get('state', '')}, Pincode: {row.get('pincode', '')}")
                        st.text(f"Issuer: {row.get('issuer_name', '')} ({row.get('issuer_id', '')}), Token Version: {row.get('token_version', '')}")
                        st.text(f"KYC Verified: {row.get('kyc_verified_date', '')} | Expires On: {row.get('kyc_expires_on', '')} | Status: {status_text}")
                        for label in ["client_photo", "signature_image"]:
                            if label in row and row[label]:
                                try:
                                    img = Image.open(BytesIO(base64.b64decode(row[label])))
                                    st.image(img, caption=label)
                                except Exception:
                                    st.warning(f"Cannot display {label}")
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            if st.button("Renew KYC"):
                                try:
                                    rr = requests.post(f"{BASE_URL}/renew/{row.get('token_id')}", timeout=5)
                                    if rr.status_code == 200:
                                        st.success("Renewed (server)")
                                        df = pd.read_sql_query("SELECT * FROM tokens WHERE token_id=?", conn, params=(token_id_input.strip(),))
                                        df_clean = decode_payload(df)
                                        row = df_clean.iloc[0]
                                    else:
                                        st.error(f"Renew failed: {rr.status_code}")
                                except Exception as e:
                                    st.error(f"Renew request failed: {e}")
                        with col2:
                            if st.button("Revoke Token"):
                                try:
                                    rr = requests.post(f"{BASE_URL}/revoke/{row.get('token_id')}", timeout=5)
                                    if rr.status_code == 200:
                                        st.warning("Revoked (server)")
                                        df = pd.read_sql_query("SELECT * FROM tokens WHERE token_id=?", conn, params=[token_id_input.strip()])

                                        df_clean = decode_payload(df)
                                        row = df_clean.iloc[0]
                                        st.rerun() if hasattr(st, "rerun") else None
                                    else:
                                        st.error(f"Revoke failed: {rr.status_code}")
                                except Exception as e:
                                    st.error(f"Revoke request failed: {e}")
                        with col3:
                            if st.button("Prepare Download Excel"):
                                try:
                                    df_for_download = pd.DataFrame([row])
                                    xlsx_bytes = df_to_excel_bytes(df_for_download)
                                    st.session_state.single_token_excel = {
                                        "bytes": xlsx_bytes,
                                        "filename": f"{row.get('token_id')}.xlsx"
                                    }
                                    st.success("Excel prepared; click the Download button below")
                                except Exception as e:
                                    st.error(f"Prepare download failed: {e}")
                        if st.session_state.single_token_excel:
                            st.download_button(
                                "Download Excel (single token)",
                                st.session_state.single_token_excel["bytes"],
                                st.session_state.single_token_excel["filename"],
                                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                            )
                    else:
                        st.warning("Token not found")
        else:
            query = "SELECT * FROM tokens WHERE 1=1"
            params = []

            if city_filter:
                query += " AND LOWER(city) LIKE ?"
                params.append(f"%{city_filter}%")
            if state_filter:
                query += " AND LOWER(state) LIKE ?"
                params.append(f"%{state_filter}%")
            if issuer_filter:
                query += " AND LOWER(issuer_name) LIKE ?"
                params.append(f"%{issuer_filter}%")

            df = pd.read_sql_query(query, conn, params=params)

            if not df.empty:
                df_clean = decode_payload(df)
                df_clean["aadhaar_masked"] = df_clean["aadhaar_masked"].astype(str)

                st.subheader("Filter Tokens")

                city_filter = ""
                state_filter = ""
                issuer_filter = ""
                status_filter = "All"

                filter_col1, filter_col2 = st.columns(2)
                with filter_col1:
                    city_filter = st.text_input("City Filter", value=city_filter).strip().lower()
                    state_filter = st.text_input("State Filter", value=state_filter).strip().lower()
                with filter_col2:
                    issuer_filter = st.text_input("Issuer Filter", value=issuer_filter).strip().lower()
                    status_filter = st.selectbox("KYC Status", ["All", "Active", "Expired", "Revoked"], index=0)

                df_display = df_clean.copy()
                if city_filter:
                    df_display = df_display[df_display["city"].str.lower().str.contains(city_filter)]
                if state_filter:
                    df_display = df_display[df_display["state"].str.lower().str.contains(state_filter)]
                if issuer_filter:
                    df_display = df_display[df_display["issuer_name"].str.lower().str.contains(issuer_filter)]

                
                df_display["kyc_status"] = df_display.apply(compute_status, axis=1)
                if status_filter != "All":
                    df_display = df_display[df_display["kyc_status"].str.lower() == status_filter.lower()]

                for _, row in df_display.iterrows():
                    expired = row.get("kyc_status", "Active") == "Expired"
                    revoked_flag = str(row.get("status", "")).lower() == "revoked"
                    status_text = "❌ Revoked" if revoked_flag else ("❌ Expired" if expired else "✅ Active")
                    st.markdown(f"---\n**Token ID:** {row.get('token_id', '')}")
                    st.text(f"Name: {row.get('full_name', '')}, Aadhaar: {row.get('aadhaar_masked', '')}, DOB: {row.get('dob', '')}")
                    st.text(f"City: {row.get('city', '')}, State: {row.get('state', '')}, Pincode: {row.get('pincode', '')}")
                    st.text(f"Issuer: {row.get('issuer_name', '')} ({row.get('issuer_id', '')}), Token Version: {row.get('token_version', '')}")
                    st.text(f"KYC Verified: {row.get('kyc_verified_date', '')} | Expires On: {row.get('kyc_expires_on', '')} | Status: {status_text}")
                    for label in ["client_photo", "signature_image"]:
                        if label in row and row[label]:
                            try:
                                img = Image.open(BytesIO(base64.b64decode(row[label])))
                                st.image(img, caption=label)
                            except Exception:
                                st.warning(f"Cannot display {label}")
                    col1, col2 = st.columns(2)
                    with col1:
                        if st.button(f"Renew KYC {row.get('token_id', '')}"):
                            try:
                                rr = requests.post(f"{BASE_URL}/renew/{row.get('token_id')}", timeout=5)
                                if rr.status_code == 200:
                                    st.success("Renewed (server)")
                                else:
                                    st.error(f"Renew failed: {rr.status_code}")
                            except Exception as e:
                                st.error(f"Renew request failed: {e}")
                    with col2:
                        if st.button(f"Revoke Token {row.get('token_id', '')}"):
                            try:
                                rr = requests.post(f"{BASE_URL}/revoke/{row.get('token_id')}", timeout=5)
                                if rr.status_code == 200:
                                    st.warning("Revoked (server)")
                                else:
                                    st.error(f"Revoke failed: {rr.status_code}")
                            except Exception as e:
                                st.error(f"Revoke request failed: {e}")
                st.subheader("Download Filtered/All Tokens")
                cold1, cold2 = st.columns([2,1])
                with cold1:
                    if st.button("Prepare Download (Filtered/All)"):
                        try:
                            issuer_param = issuer_filter if 'issuer_filter' in locals() and issuer_filter else None
                            url = f"{BASE_URL}/download/all"
                            if issuer_param:
                                url += f"?issuer_id={issuer_param}"
                            dl = requests.get(url, timeout=15)
                            if dl.status_code == 200:
                                xlsx_data = csv_to_excel_bytes(dl.content)
                                st.session_state.all_tokens_excel = {
                                    "bytes": xlsx_data,
                                    "filename": "tokens_export.xlsx"
                                }
                                st.success("Export prepared; click Download below")
                            else:
                                st.error(f"Server download failed: {dl.status_code}")
                        except Exception as e:
                            st.error(f"Download request failed: {e}")
                with cold2:
                    if st.session_state.all_tokens_excel:
                        st.download_button(
                            "Download Excel (filtered/all)",
                            st.session_state.all_tokens_excel["bytes"],
                            st.session_state.all_tokens_excel["filename"],
                            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                        )
            else:
            st.info("No tokens found in the database")
    except Exception as e:
        st.error(f"Error reading database: {e}")
    conn.close()

with tabs[4]:
    st.header("Consent Manager")

    st.subheader("Create Consent Request")

    colA, colB = st.columns(2)
    with colA:
        token_id_input = st.text_input("Token ID")
        institution_id_input = st.text_input("Institution ID")
    with colB:
        fields_input = st.multiselect(
            "Fields to Request",
            ["name", "dob", "aadhaar_ref", "address", "phone", "email"]
        )
        purpose_input = st.text_input("Purpose")

    if st.button("Submit Consent Request"):
        if not token_id_input or not institution_id_input or not fields_input or not purpose_input:
            st.error("All fields must be filled.")
        else:
            payload = {
                "token_id": token_id_input,
                "institution_id": institution_id_input,
                "requested_fields": [str(f) for f in fields_input],
                "purpose": purpose_input
            }

            try:
                res = requests.post(f"{BASE_URL}/consent/request", json=payload)
                if res.status_code == 200:
                    st.success(f"Consent Requested (ID: {res.json()['consent_id']})")
                else:
                    st.error(f"Request Failed: {res.text}")
            except Exception as e:
                st.error(f"Request Failed: {e}")

    st.markdown("---")


    st.subheader("View & Manage Consent Requests")

    status_filter = st.selectbox(
        "Filter by Status",
        ["ALL", "pending", "approved", "expired"]
    )

    try:
        r = requests.get(f"{BASE_URL}/consent/all")
        if r.status_code == 200:
            consents = r.json().get("consents", [])
        else:
            consents = []
            st.error("Failed to load consent data.")
    except Exception as e:
        st.error(f"Error: {e}")
        consents = []

    df = pd.DataFrame(consents)

    if not df.empty and status_filter != "ALL":
        df = df[df["status"] == status_filter]

    def color_status(val):
        if val.lower() == "approved":
            return "background-color: #c8e6c9"
        elif val.lower() == "pending":
            return "background-color: #fff9c4"
        elif val.lower() == "expired":
            return "background-color: #ffcccb"
        return ""

    if not df.empty:
        st.dataframe(df.style.applymap(color_status, subset=["status"]), use_container_width=True)
    else:
        st.info("No consent records available.")

    st.markdown("### Approve Consent Request")
    selected_consent_id = st.text_input("Enter Consent ID to Approve")

    if st.button("Approve Consent"):
        if selected_consent_id:
            try:
                res = requests.post(
                    f"{BASE_URL}/consent/approve",
                    json={"consent_id": selected_consent_id}
                )
                if res.status_code == 200:
                    st.success("Consent Approved Successfully")
                    st.rerun()
                else:
                    st.error("Approval Failed")
            except Exception as e:
                st.error(f"Request Failed: {e}")
        else:
            st.error("Enter Consent ID first.")


with tabs[5]:
    st.header("Audit Logs")
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute("SELECT * FROM audit_logs ORDER BY ts DESC")
    logs = cur.fetchall()

    df_logs = pd.DataFrame(logs, columns=[
        "id", "action", "token_id", "issuer_id", "details", "ts"
    ])

    st.dataframe(df_logs, use_container_width=True)
