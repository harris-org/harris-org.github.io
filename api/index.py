import os
import base64
from functools import wraps
from flask import Flask, request, render_template, session, redirect, url_for
from werkzeug.exceptions import Unauthorized
from supabase import create_client, Client
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

app = Flask(__name__, template_folder="../templates")

# This secret key is required to encrypt the user's session memory securely
app.secret_key = os.environ.get("SYSTEM_MASTER_KEY", "fallback-secret-for-local-testing")

URL = os.environ.get("SUPABASE_URL")
KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(URL, KEY)

# ==========================================
# CONSTANTS & HELPERS
# ==========================================

# Centralize role names to avoid typos and make changes easier
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
            # 1. Check if they have a session badge at all
            if 'user_role' not in session:
                return redirect(url_for('login', error="Please log in first."))
            
            # 2. Check if their badge matches the room's required role
            if session['user_role'] != role:
                # Use a template for the error page instead of inline HTML.
                return render_template('403.html'), 403
            
            # 3. Pass checks, let them in!
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==========================================
# HELPER FUNCTIONS
# ==========================================
def _redirect_to_dashboard(role):
    """Redirects user to their dashboard based on role."""
    dashboard_route = ROLE_DASHBOARDS.get(role)
    return redirect(url_for(dashboard_route)) if dashboard_route else redirect(url_for('login'))

# ==========================================
# ROUTES
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
            # Supabase-py raises an exception on login failure, so we don't need to check the response.
            supabase.auth.sign_in_with_password({"email": email, "password": password})
            profile_response = supabase.table("Profiles").select("role").eq("email", email).execute()
            
            if len(profile_response.data) > 0:
                user_role = profile_response.data[0]['role']
                
                if user_role in ROLE_DASHBOARDS:
                    # PIN THE BADGE TO THEIR SHIRT (Save to Session Memory)
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
    session.clear() # Destroys the memory badge
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
        
        # Combine the data into a single string to encrypt
        raw_data = f"Patient: {patient_name} | Diagnosis: {medical_notes}"
        
        try:
            # 1. Retrieve the 256-bit Master Key from Vercel environment variables
            master_key_hex = os.environ.get("SYSTEM_MASTER_KEY")
            if not master_key_hex:
                raise Exception("Encryption Key is missing from the server environment.")
            
            # Convert the hex string back into bytes for the cryptography library
            master_key = bytes.fromhex(master_key_hex)
            
            # 2. Initialize the AES-GCM Cipher
            # LO2/LO4 Justification: AES-GCM provides Authenticated Encryption.
            # It ensures both Confidentiality (hiding data) and Integrity (detecting tampering via the auth tag),
            # satisfying GDPR Article 9 requirements for state-of-the-art security of health data.
            aesgcm = AESGCM(master_key)
            
            # 3. Generate a secure, random 96-bit Nonce (Number used ONCE)
            nonce = os.urandom(12)
            
            # 4. Encrypt the data (AESGCM automatically attaches the authentication tag to the ciphertext)
            ciphertext = aesgcm.encrypt(nonce, raw_data.encode('utf-8'), None)
            
            # 5. Encode to Base64 so the binary data can be safely stored as text in PostgreSQL
            nonce_b64 = base64.b64encode(nonce).decode('utf-8')
            ct_b64 = base64.b64encode(ciphertext).decode('utf-8')
            
            # 6. Save the locked record to Supabase
            supabase.table('MedicalRecords').insert({
                "clinician_email": session['user_email'],
                "encrypted_payload": ct_b64,
                "nonce": nonce_b64
            }).execute()
            
            success_msg = "Patient record successfully encrypted (AES-256-GCM) and stored securely."
            
        except Exception as e:
            error_msg = f"Cryptographic Error: {str(e)}"

    return render_template('clinician.html', email=session['user_email'], success=success_msg, error=error_msg)

@app.route('/researcher')
@require_role(Roles.RESEARCHER)
def researcher_dashboard():
    return render_template('researcher.html', email=session['user_email'])

@app.route('/auditor')
@require_role(Roles.AUDITOR)
def auditor_dashboard():
    return render_template('auditor.html', email=session['user_email'])

if __name__ == '__main__':
    app.run()