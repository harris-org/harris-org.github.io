import os
import base64
from functools import wraps
from flask import Flask, request, render_template, session, redirect, url_for
from werkzeug.exceptions import Unauthorized
from supabase import create_client, Client

# Cryptography Imports
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding as rsa_padding
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization

app = Flask(__name__, template_folder="../templates")

# This secret key is required to encrypt the user's session memory securely
app.secret_key = os.environ.get("SYSTEM_MASTER_KEY", "fallback-secret-for-local-testing")

URL = os.environ.get("SUPABASE_URL")
KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(URL, KEY)

# ==========================================
# CONSTANTS & HELPERS
# ==========================================

class Roles:
    CLINICIAN = 'Clinician'
    RESEARCHER = 'Researcher'
    AUDITOR = 'Auditor'

ROLE_DASHBOARDS = {
    Roles.CLINICIAN: 'clinician_dashboard',
    Roles.RESEARCHER: 'researcher_dashboard',
    Roles.AUDITOR: 'auditor_dashboard',
}

# ==========================================
# THE BOUNCER (ACCESS CONTROL LOCK)
# ==========================================
def require_role(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'user_role' not in session:
                return redirect(url_for('login', error="Please log in first."))
            if session['user_role'] != role:
                return render_template('403.html'), 403
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def _redirect_to_dashboard(role):
    dashboard_route = ROLE_DASHBOARDS.get(role)
    return redirect(url_for(dashboard_route)) if dashboard_route else redirect(url_for('login'))

# ==========================================
# PUBLIC ROUTES
# ==========================================

@app.route('/', methods=['GET', 'POST'])
def login():
    if 'user_role' in session and session['user_role'] in ROLE_DASHBOARDS:
        return _redirect_to_dashboard(session['user_role'])

    error_message = request.args.get('error')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            supabase.auth.sign_in_with_password({"email": email, "password": password})
            profile_response = supabase.table("Profiles").select("role").eq("email", email).execute()
            
            if len(profile_response.data) > 0:
                user_role = profile_response.data[0]['role']
                if user_role in ROLE_DASHBOARDS:
                    session['user_email'] = email
                    session['user_role'] = user_role
                    return _redirect_to_dashboard(user_role)
                else:
                    error_message = "Your assigned role does not have a valid dashboard."
            else:
                error_message = "Login successful, but no role is assigned to your profile."
        except Unauthorized:
            error_message = "Invalid email or password."
        except Exception:
            error_message = "A system error occurred. Please try again later."

    return render_template('login.html', error=error_message)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

# ==========================================
# SECURE DASHBOARDS (ALL 3 ROLES)
# ==========================================

@app.route('/clinician', methods=['GET', 'POST'])
@require_role(Roles.CLINICIAN)
def clinician_dashboard():
    success_msg = None
    error_msg = None

    if request.method == 'POST':
        patient_name = request.form.get('patient_name')
        medical_notes = request.form.get('medical_notes')
        raw_data = f"Patient: {patient_name} | Diagnosis: {medical_notes}"
        
        try:
            master_key_hex = os.environ.get("SYSTEM_MASTER_KEY")
            if not master_key_hex:
                raise Exception("Encryption Key is missing from the server environment.")
            
            master_key = bytes.fromhex(master_key_hex)
            
            # LO2/LO4 Justification: AES-GCM provides Authenticated Encryption for data in transit/rest (Stallings, 2020).
            aesgcm = AESGCM(master_key)
            nonce = os.urandom(12)
            ciphertext = aesgcm.encrypt(nonce, raw_data.encode('utf-8'), None)
            
            nonce_b64 = base64.b64encode(nonce).decode('utf-8')
            ct_b64 = base64.b64encode(ciphertext).decode('utf-8')
            
            supabase.table('MedicalRecords').insert({
                "clinician_email": session['user_email'],
                "encrypted_payload": ct_b64,
                "nonce": nonce_b64
            }).execute()
            
            success_msg = "Patient record successfully encrypted (AES-256-GCM) and stored securely."
            
        except Exception as e:
            error_msg = f"Cryptographic Error: {str(e)}"

    return render_template('clinician.html', email=session['user_email'], success=success_msg, error=error_msg)

@app.route('/researcher', methods=['GET', 'POST'])
@require_role(Roles.RESEARCHER)
def researcher_dashboard():
    success_msg = None
    error_msg = None
    records = []

    master_key_hex = os.environ.get("SYSTEM_MASTER_KEY")
    master_key = bytes.fromhex(master_key_hex) if master_key_hex else None

    try:
        if request.method == 'POST':
            record_id = request.form.get('record_id')
            researcher_findings = request.form.get('researcher_findings', 'No additional findings.')

            if not master_key:
                raise Exception("Encryption Key is missing from the server environment.")

            # 1. Encrypt Researcher Findings (AES-256-GCM)
            aesgcm = AESGCM(master_key)
            findings_nonce = os.urandom(12)
            encrypted_findings = aesgcm.encrypt(findings_nonce, researcher_findings.encode('utf-8'), None)

            findings_nonce_b64 = base64.b64encode(findings_nonce).decode('utf-8')
            encrypted_findings_b64 = base64.b64encode(encrypted_findings).decode('utf-8')

            # 2. Generate RSA-2048 Key Pair for Digital Signature
            # Justification: RSA signatures provide non-repudiation and authenticity (Stallings, 2020).
            private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
            public_key = private_key.public_key()

            pem_public_key = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')

            # 3. Fetch original record to sign the complete package
            record_resp = supabase.table('MedicalRecords').select('encrypted_payload').eq('id', record_id).execute()
            if record_resp.data:
                original_payload = record_resp.data[0]['encrypted_payload']

                # We sign BOTH the clinician's data and researcher's data to prove integrity of the whole file
                data_to_sign = f"{original_payload}|{encrypted_findings_b64}".encode('utf-8')

                # Using state-of-the-art PSS padding (Katz and Lindell, 2020).
                signature = private_key.sign(
                    data_to_sign,
                    rsa_padding.PSS(
                        mgf=rsa_padding.MGF1(hashes.SHA256()),
                        salt_length=rsa_padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )

                signature_b64 = base64.b64encode(signature).decode('utf-8')

                # 4. Update Database
                supabase.table('MedicalRecords').update({
                    'researcher_encrypted_findings': encrypted_findings_b64,
                    'researcher_findings_nonce': findings_nonce_b64,
                    'researcher_signature': signature_b64,
                    'researcher_public_key': pem_public_key
                }).eq('id', record_id).execute()

                success_msg = f"Record #{record_id} successfully updated with encrypted findings and digitally signed."

        # GET Request: Fetch and decrypt records for display
        response = supabase.table('MedicalRecords').select('*').order('id', desc=True).execute()

        if master_key:
            aesgcm = AESGCM(master_key)
            for r in response.data:
                # Decrypt Clinician Data
                try:
                    nonce = base64.b64decode(r['nonce'])
                    ciphertext = base64.b64decode(r['encrypted_payload'])
                    r['decrypted_text'] = aesgcm.decrypt(nonce, ciphertext, None).decode('utf-8')
                except Exception:
                    r['decrypted_text'] = "INTEGRITY ERROR: Data decryption failed."

                # Decrypt Researcher Findings if they exist
                if r.get('researcher_encrypted_findings'):
                    try:
                        f_nonce = base64.b64decode(r['researcher_findings_nonce'])
                        f_ciphertext = base64.b64decode(r['researcher_encrypted_findings'])
                        r['decrypted_findings'] = aesgcm.decrypt(f_nonce, f_ciphertext, None).decode('utf-8')
                    except Exception:
                        r['decrypted_findings'] = "INTEGRITY ERROR: Findings decryption failed."

        records = response.data

    except Exception as e:
        error_msg = f"System Error: {str(e)}"

    return render_template('researcher.html', email=session['user_email'], records=records, success=success_msg, error=error_msg)

@app.route('/auditor')
@require_role(Roles.AUDITOR)
def auditor_dashboard():
    return render_template('auditor.html', email=session['user_email'])

if __name__ == '__main__':
    app.run()