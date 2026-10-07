"""
Remediated & Hardened Cyber Security Utility Web Application
Stack: Python 3, Flask, SQLite3, Flask-WTF, Werkzeug
Remediation for CodeAlpha Cyber Security Task 3: Secure Coding Review.
Addresses: SQLi, Plaintext Passwords, Hardcoded Secrets, Reflected XSS, SSRF, Debug Mode, CSRF.
"""

import os
import sqlite3
import ipaddress
import socket
from urllib.parse import urlparse
import requests
from dotenv import load_dotenv
from flask import Flask, request, render_template, redirect, session, jsonify, abort, url_for
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect

# ==============================================================================
# 1. ENVIRONMENT CONFIGURATION & SECRETS MANAGEMENT (Remediation 4.3)
env_file = os.path.join(os.path.dirname(__file__), '.env')
load_dotenv(env_file)
load_dotenv()

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
app = Flask(__name__, template_folder=template_dir)

# Load secret key from environment; enforce runtime fail-fast if absent
SECRET_KEY = os.environ.get("FLASK_SECRET_KEY")
if not SECRET_KEY:
    raise RuntimeError(
        "CRITICAL SECURITY CONFIGURATION ERROR: FLASK_SECRET_KEY is not defined! "
        "Populate .env using .env.example before launching the application."
    )
app.secret_key = SECRET_KEY

# Optional 3rd party threat intel key from environment
THREAT_INTEL_API_KEY = os.environ.get("THREAT_INTEL_API_KEY", "")

# ==============================================================================
# 2. CSRF PROTECTION & SESSION COOKIE HARDENING (Remediation 4.7)
# ==============================================================================
csrf = CSRFProtect(app)

app.config.update(
    # Mitigate session hijacking via XSS
    SESSION_COOKIE_HTTPONLY=True,
    # Mitigate Cross-Site Request Forgery via Strict/Lax SameSite
    SESSION_COOKIE_SAMESITE='Lax',
    # Enable Secure flag (HTTPS required in production)
    SESSION_COOKIE_SECURE=os.environ.get("FLASK_ENV") == "production",
    PERMANENT_SESSION_LIFETIME=1800,  # 30-minute idle session timeout
    MAX_CONTENT_LENGTH=1 * 1024 * 1024 # 1 MB request size limit against DoS
)

# Enforce Security Headers (CSP, HSTS, X-Frame-Options)
@app.after_request
def set_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "img-src 'self' data:; "
        "frame-ancestors 'none';"
    )
    return response

# ==============================================================================
# 3. SECURE DATABASE INITIALIZATION & ACCESS
# ==============================================================================
DB_PATH = os.path.join(os.path.dirname(__file__), "cyber_utility_secure.db")

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            email TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("SELECT COUNT(*) FROM users")
    if cursor.fetchone()[0] == 0:
        # [REMEDIATION 4.2] Strong scrypt password hashing
        admin_hash = generate_password_hash("Admin@Secure2026!", method="scrypt")
        analyst_hash = generate_password_hash("Analyst_Strong#99", method="scrypt")
        cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                       ('admin', admin_hash, 'admin@cyberutility.local'))
        cursor.execute("INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
                       ('analyst', analyst_hash, 'analyst@cyberutility.local'))
    conn.commit()
    conn.close()

init_db()

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

# ==============================================================================
# 4. SECURE AUTHENTICATION (Remediation 4.1 SQLi & 4.2 Hashing)
# ==============================================================================
@app.route('/')
def index():
    return render_template('index.html', user=session.get('user'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template('login.html')
        
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    if not username or not password:
        return render_template('login.html', error="Username and password are required."), 400
        
    conn = get_db()
    cursor = conn.cursor()
    
    # [REMEDIATION 4.1 - PARAMETERIZED QUERY]
    # Uses SQL placeholders '?' to separate SQL semantics from user input
    cursor.execute(
        "SELECT id, username, password_hash FROM users WHERE username = ?", 
        (username,)
    )
    user_row = cursor.fetchone()
    conn.close()
    
    # [REMEDIATION 4.2 - CONSTANT-TIME PASSWORD VERIFICATION]
    if user_row and check_password_hash(user_row['password_hash'], password):
        # Regenerate session token on login to prevent session fixation
        session.clear()
        session['user'] = user_row['username']
        session['user_id'] = user_row['id']
        return redirect(url_for('dashboard'))
        
    return render_template('login.html', error="Invalid username or password."), 401

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template('register.html')
        
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    email = request.form.get('email', '').strip()
    
    # Input validation
    if len(username) < 3 or len(username) > 32 or not username.isalnum():
        return render_template('register.html', error="Username must be alphanumeric and 3-32 chars long."), 400
        
    if len(password) < 10:
        return render_template('register.html', error="Password must be at least 10 characters long."), 400
        
    # [REMEDIATION 4.2 - SECURE SALTED HASH]
    hashed_pwd = generate_password_hash(password, method='scrypt')
    
    conn = get_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO users (username, password_hash, email) VALUES (?, ?, ?)",
            (username, hashed_pwd, email)
        )
        conn.commit()
        return redirect(url_for('login'))
    except sqlite3.IntegrityError:
        return render_template('register.html', error="Username already exists."), 409
    finally:
        conn.close()

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect(url_for('login'))
    return render_template('dashboard.html', user=session['user'])

# ==============================================================================
# 5. PASSWORD STRENGTH CHECKER (Remediation 4.4 - Auto-Escaping & Jinja2)
# ==============================================================================
@app.route('/check-password', methods=['GET', 'POST'])
def check_password():
    if request.method == 'GET':
        return render_template('password_checker.html')
        
    password = request.form.get('password', '')
    
    length = len(password)
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(c in "!@#$%^&*()-_=+[]{}|;:,.<>?" for c in password)
    
    score = 0
    if length >= 8: score += 20
    if length >= 12: score += 15
    if length >= 16: score += 15
    if has_upper: score += 15
    if has_lower: score += 10
    if has_digit: score += 15
    if has_special: score += 10
    
    verdict = "Weak" if score < 50 else ("Moderate" if score < 75 else "Strong")
    
    tips = []
    if length < 12: tips.append("Increase length to at least 12 characters.")
    if not has_upper: tips.append("Include uppercase letters (A-Z).")
    if not has_digit: tips.append("Include numbers (0-9).")
    if not has_special: tips.append("Include special characters (!@#$%...).")
    
    # [REMEDIATION 4.4 - JINJA2 AUTO-ESCAPING]
    # Renders through HTML template engine where variables are HTML-entity encoded automatically
    return render_template(
        'password_checker.html',
        password_length=length,
        score=score,
        verdict=verdict,
        tips=tips,
        submitted=True
    )

# ==============================================================================
# 6. URL & PHISHING SCANNER (Remediation 4.5 - SSRF Protection)
# ==============================================================================
def validate_url_for_ssrf(target_url: str) -> tuple[bool, str]:
    """
    Validates user-submitted URL against SSRF threats:
    1. Enforces HTTP/HTTPS protocol scheme.
    2. Resolves DNS hostname to target IP addresses.
    3. Blocks loopback (127.0.0.1, ::1), private RFC1918, link-local, cloud metadata (169.254.x.x).
    """
    try:
        parsed = urlparse(target_url)
        if parsed.scheme.lower() not in ('http', 'https'):
            return False, "Invalid protocol scheme. Only HTTP and HTTPS are permitted."
            
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL hostname."
            
        # Prohibit known cloud metadata and internal hostnames
        if hostname.lower() in ('localhost', 'metadata.google.internal'):
            return False, "Target hostname is restricted."
            
        # DNS resolution to verify all target IPs
        addr_info = socket.getaddrinfo(hostname, parsed.port or (443 if parsed.scheme == 'https' else 80))
        for _, _, _, _, sockaddr in addr_info:
            ip = ipaddress.ip_address(sockaddr[0])
            if ip.is_loopback:
                return False, f"Denied access to loopback address ({ip})."
            if ip.is_private:
                return False, f"Denied access to private RFC 1918 network ({ip})."
            if ip.is_link_local:
                return False, f"Denied access to link-local / cloud metadata space ({ip})."
            if ip.is_reserved or ip.is_multicast:
                return False, f"Denied access to reserved address space ({ip})."
                
        return True, ""
    except socket.gaierror:
        return False, "Hostname resolution failed. Host does not exist."
    except Exception as e:
        return False, f"URL validation error: {str(e)}"

@app.route('/check-url', methods=['GET', 'POST'])
def check_url():
    if request.method == 'GET':
        return render_template('url_checker.html')
        
    target_url = request.form.get('url', '').strip()
    if not target_url:
        return render_template('url_checker.html', error="URL parameter is required."), 400
        
    # User convenience: prepend https:// if scheme is missing
    normalized_url = target_url
    if not target_url.startswith(('http://', 'https://', 'ftp://', 'file://')):
        normalized_url = 'https://' + target_url

    # [REMEDIATION 4.5 - VALIDATE BEFORE DISPATCHING]
    is_safe, failure_reason = validate_url_for_ssrf(normalized_url)
    if not is_safe:
        return render_template(
            'url_checker.html', 
            error=f"SSRF Protection Block: {failure_reason}",
            blocked_url=normalized_url
        ), 400
        
    try:
        # Strict timeout, disabled redirects to prevent Open Redirect SSRF bypass
        response = requests.get(
            normalized_url,
            timeout=3.0,
            allow_redirects=False,
            headers={"User-Agent": "CyberUtility-SecurityScanner/2.0"}
        )
        
        result_data = {
            "target": normalized_url,
            "status_code": response.status_code,
            "content_type": response.headers.get("Content-Type", "Unknown"),
            "body_preview": response.text[:400] if response.text else "",
            "safe": True
        }
        return render_template('url_checker.html', result=result_data)
    except requests.exceptions.Timeout:
        return render_template('url_checker.html', error="Request timed out after 3.0s."), 504
    except requests.exceptions.RequestException as e:
        return render_template('url_checker.html', error=f"HTTP request error: {str(e)}"), 502

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

# ==============================================================================
# 7. PRODUCTION RUNNER (Remediation 4.6 - Debug Mode Disabled)
# ==============================================================================
if __name__ == '__main__':
    # Debug mode is strictly controlled via environment variable, never hardcoded to True
    debug_flag = os.environ.get("FLASK_DEBUG", "0").lower() in ("1", "true")
    server_port = int(os.environ.get("PORT", 5001))
    
    print(f"[*] Starting Secure Cyber Utility on 127.0.0.1:{server_port} (Debug={debug_flag})")
    app.run(host='127.0.0.1', port=server_port, debug=debug_flag)
