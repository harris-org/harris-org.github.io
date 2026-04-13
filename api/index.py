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
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        try:
            response = supabase.auth.sign_in_with_password({"email": email, "password": password})
            return "Login successful! Welcome to the application."
        except Exception as e:
            error_message = "Invalid email or password. Please try again."
    return render_template('login.html', error=error_message)

if __name__ == '__main__':
    app.run()