import os
from functools import wraps
from flask import Flask, request, render_template, session, redirect, url_for
from supabase import create_client, Client

app = Flask(__name__, template_folder="../templates")

# This secret key is required to encrypt the user's session memory securely
app.secret_key = os.environ.get("SYSTEM_MASTER_KEY", "fallback-secret-for-local-testing")

URL = os.environ.get("SUPABASE_URL")
KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(URL, KEY)

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
                # INSTANT 403 FORBIDDEN PAGE (Stops the redirect loop)
                return """
                <div style='font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; text-align: center; margin-top: 100px; color: #333;'>
                    <h2 style='color: #ef4444;'>🛑 Access Denied</h2>
                    <p>Your current role does not have permission to view this page.</p>
                    <br>
                    <a href='/' style='padding: 10px 16px; background: #111; color: white; text-decoration: none; border-radius: 6px; font-weight: 500; display: inline-block; margin-top: 15px;'>Return to Dashboard</a>
                </div>
                """, 403
            
            # 3. Pass checks, let them in!
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# ==========================================
# ROUTES
# ==========================================

@app.route('/', methods=['GET', 'POST'])
def login():
    # If they are already logged in, route them to their respective dashboards
    if 'user_role' in session:
        if session['user_role'] == 'Clinician':
            return redirect(url_for('clinician_dashboard'))
        elif session['user_role'] == 'Researcher':
            return redirect(url_for('researcher_dashboard'))
        elif session['user_role'] == 'Auditor':
            return redirect(url_for('auditor_dashboard'))

    error_message = request.args.get('error')

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            auth_response = supabase.auth.sign_in_with_password({"email": email, "password": password})
            profile_response = supabase.table("Profiles").select("role").eq("email", email).execute()
            
            if len(profile_response.data) > 0:
                user_role = profile_response.data[0]['role']
                
                # PIN THE BADGE TO THEIR SHIRT (Save to Session Memory)
                session['user_email'] = email
                session['user_role'] = user_role
                
                # Route to the correct locked door
                if user_role == 'Clinician':
                    return redirect(url_for('clinician_dashboard'))
                elif user_role == 'Researcher':
                    return redirect(url_for('researcher_dashboard'))
                elif user_role == 'Auditor':
                    return redirect(url_for('auditor_dashboard'))
            else:
                error_message = "No role assigned in the database."

        except Exception as e:
            error_message = f"System Report: {str(e)}"

    return render_template('login.html', error=error_message)

@app.route('/logout')
def logout():
    session.clear() # Destroys the memory badge
    return redirect(url_for('login'))

# ==========================================
# SECURE DASHBOARDS (ALL 3 ROLES)
# ==========================================

@app.route('/clinician')
@require_role('Clinician')
def clinician_dashboard():
    return render_template('clinician.html', email=session['user_email'])

@app.route('/researcher')
@require_role('Researcher')
def researcher_dashboard():
    return render_template('researcher.html', email=session['user_email'])

@app.route('/auditor')
@require_role('Auditor')
def auditor_dashboard():
    return render_template('auditor.html', email=session['user_email'])

if __name__ == '__main__':
    app.run()