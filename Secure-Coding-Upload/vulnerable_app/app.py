"""
Vulnerable Cyber Security Utility Web Application
Stack: Python 3, Flask, SQLite3
WARNING: This application contains intentional vulnerabilities for educational,
auditing, and security code review purposes (CodeAlpha Cyber Security Task 3).
"""

import os
import sqlite3
import requests
from flask import Flask, request, render_template, redirect, session, jsonify

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
app = Flask(__name__, template_folder=template_dir)

# [VULNERABILITY 4.3 - HARDCODED SECRETS]
# Secret keys committed directly to source code
app.secret_key = "supersecret123"
API_KEY = "AIzaSyD4xxxxxxxxxxxxxxxxxxxx"
THREAT_INTEL_URL = "https://threat-intel.internal.api/v1/scan"

DB_PATH = os.path.join(os.path.dirname(__file__), "cyber_utility_vuln.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            password TEXT,
            email TEXT
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # [VULNERABILITY 4.2 - PLAINTEXT PASSWORDS]
        cursor.execute("INSERT INTO users (username, password, email) VALUES ('admin', 'Admin@123', 'admin@cyberutility.local')")
        cursor.execute("INSERT INTO users (username, password, email) VALUES ('analyst', 'hunter2', 'analyst@cyberutility.local')")
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

@app.route('/')
def index():
    return render_template('index.html', user=session.get('user'))

# [VULNERABILITY 4.1 - SQL INJECTION]
# Direct string formatting into SQL query allows authentication bypass
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
        
    user = request.form.get('username', '')
    pwd = request.form.get('password', '')
    
    conn = get_db()
    cursor = conn.cursor()
    # Flaw: String formatting introduces classic SQL Injection
    query = f"SELECT * FROM users WHERE username='{user}' AND password='{pwd}'"
    print(f"[DEBUG EXEC SQL]: {query}")
    
    try:
        cursor.execute(query)
        account = cursor.fetchone()
        if account:
            session['user'] = account['username']
            return redirect('/dashboard')
        else:
            return render_template('login.html', error='Invalid username or password')
    except Exception as e:
        # [VULNERABILITY 4.6 - VERBOSE ERROR LEAK]
        return f"Database Error: {str(e)}", 500

# [VULNERABILITY 4.2 - PLAINTEXT PASSWORDS & 4.7 NO CSRF]
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
        
    username = request.form.get('username')
    password = request.form.get('password')
    email = request.form.get('email', '')
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        # Passwords stored in raw plaintext
        cursor.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (username, password, email))
        conn.commit()
        return redirect('/login')
    except Exception as e:
        return render_template('register.html', error=f"Registration failed: {str(e)}")

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')
    return render_template('dashboard.html', user=session['user'])

# [VULNERABILITY 4.4 - REFLECTED CROSS-SITE SCRIPTING (XSS)]
# Password result string concatenated directly into returned HTML without Jinja auto-escaping
@app.route('/check-password', methods=['GET', 'POST'])
def check_password():
    if request.method == 'GET':
        return render_template('password_checker.html')
        
    pwd = request.form.get('password', '')
    length = len(pwd)
    
    score = 0
    if length >= 8: score += 25
    if any(c.isupper() for c in pwd): score += 25
    if any(c.isdigit() for c in pwd): score += 25
    if any(c in "!@#$%^&*()-_=+" for c in pwd): score += 25
    
    verdict = "Weak" if score < 50 else ("Moderate" if score < 75 else "Strong")
    
    # Flaw: Reflected XSS via raw string injection
    return f"""
    <!DOCTYPE html>
    <html>
    <head><title>Result</title><link rel="stylesheet" href="/static/style.css"></head>
    <body style="font-family: sans-serif; padding: 2rem;">
        <h2>Password Strength Analysis</h2>
        <p>Password analyzed: <strong>{pwd}</strong></p>
        <p>Score: {score}% ({verdict})</p>
        <a href="/check-password">&larr; Check Another</a>
    </body>
    </html>
    """

# [VULNERABILITY 4.5 - SERVER-SIDE REQUEST FORGERY (SSRF)]
# Outbound HTTP GET to user-supplied URL with no IP filtering or protocol restrictions
@app.route('/check-url', methods=['GET', 'POST'])
def check_url():
    if request.method == 'GET':
        return render_template('url_checker.html')
        
    target_url = request.form.get('url', '')
    
    try:
        # Flaw: Server fetches internal IP (127.0.0.1, 169.254.169.254, 192.168.x.x)
        resp = requests.get(target_url, timeout=5)
        result_data = {
            "target": target_url,
            "status_code": resp.status_code,
            "content_type": resp.headers.get('Content-Type', 'Unknown'),
            "body_preview": resp.text[:400]
        }
        if request.headers.get('Accept') == 'application/json':
            return jsonify(result_data)
        return render_template('url_checker.html', result=result_data)
    except Exception as e:
        if request.headers.get('Accept') == 'application/json':
            return jsonify({"error": str(e)}), 400
        return render_template('url_checker.html', error=str(e), target=target_url), 400

@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/')

# [VULNERABILITY 4.6 - DEBUG MODE ENABLED IN PRODUCTION]
if __name__ == '__main__':
    # Debug mode enables Werkzeug PIN execution console
    app.run(host='0.0.0.0', port=5000, debug=True)
