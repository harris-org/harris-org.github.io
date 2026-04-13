import os
from flask import Flask, request, render_template
from supabase import create_client, Client

app = Flask(__name__, template_folder="../templates")

URL = os.environ.get("SUPABASE_URL")
KEY = os.environ.get("SUPABASE_KEY")
supabase: Client = create_client(URL, KEY)

@app.route('/', methods=['GET', 'POST'])
def login():
    error_message = None
    success_message = None

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            # 1. Verify the password (THIS IS SUCCEEDING!)
            auth_response = supabase.auth.sign_in_with_password({"email": email, "password": password})
            
            # 2. Look up their ID badge (Role) in the database (THIS IS CRASHING!)
            profile_response = supabase.table("profiles").select("role").eq("email", email).execute()
            
            # 3. Extract the role and create a success message
            if len(profile_response.data) > 0:
                user_role = profile_response.data[0]['role']
                success_message = f"Login successful! Welcome to the secure dashboard, {user_role}."
            else:
                success_message = "Login successful, but you don't have a role assigned yet!"

        except Exception as e:
            # WE CHANGED THIS TO REVEAL THE TRUE ERROR
            error_message = f"Python Crash Report: {str(e)}"

    # Send the messages back to the HTML page
    return render_template('login.html', error=error_message, success=success_message)

if __name__ == '__main__':
    app.run()