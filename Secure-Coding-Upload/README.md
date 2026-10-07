# CodeAlpha Task 3: Secure Coding Review & Source Code Suite

This repository contains the complete source code for **CodeAlpha Task 3: Secure Coding Review**.
It includes both the intentionally vulnerable reference application and the production-hardened secure version, accompanied by exploit demonstration scripts, test suites, and audit logs.

## Directory Structure
```
├── vulnerable_app/          # Unhardened application with 7 documented vulnerabilities
│   ├── app.py
│   ├── requirements.txt
│   └── templates/
├── secure_app/              # Hardened production-ready application
│   ├── app.py
│   ├── requirements.txt
│   ├── .env.example
│   └── templates/
├── exploits/                # Working Proof-of-Concept verification scripts
│   ├── exploit_sqli.py
│   ├── exploit_xss.py
│   └── exploit_ssrf.py
├── tests/                   # Pytest test suite for security regressions
│   └── test_security.py
├── audit/                   # Static analysis reports & submission documentation
│   ├── bandit_report.txt
│   └── Task3_Secure_Coding_Review_Report.md
└── README.md
```

## Quick Start

### ⚡ All-in-One Master Command (Run Entire Project)
You can run all regression tests, static security audits (Bandit), and exploit demonstrations in **one single command**:
```bash
python run_all.py
```
*(On Windows: `py run_all.py` or `.\secure_app\venv\Scripts\python.exe run_all.py`)*

---

### Manual Execution Steps

### 1. Run the Vulnerable App
```bash
cd vulnerable_app
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
# Runs on http://127.0.0.1:5000
```

### 2. Run the Secure Remediated App
```bash
cd secure_app
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
# Edit .env and set FLASK_SECRET_KEY
python app.py
# Runs on http://127.0.0.1:5001 with OWASP hardening
```

### 3. Run Static Analysis (Bandit)
```bash
bandit -r vulnerable_app/ -f txt
bandit -r secure_app/ -f txt
```

### 4. Run Security Regression Tests
```bash
pytest tests/test_security.py -v
```
