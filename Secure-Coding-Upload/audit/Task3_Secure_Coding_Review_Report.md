# CodeAlpha Cyber Security Internship — Task 3: Secure Coding Review

**Intern Name:** Cyber Security Intern  
**Domain:** Cyber Security  
**Task:** Task 3 - Secure Coding Review  
**Stack Audited:** Python 3 (Flask), SQLite, HTML/Jinja2  

---

## 1. Executive Summary
This report presents a comprehensive secure code review of the "Cyber Security Utility" web application (comprising Authentication, Password Evaluation, and Phishing/URL Scanner modules). Through manual line-by-line inspection and automated static analysis (`bandit`, `pip-audit`), seven distinct vulnerabilities spanning the OWASP Top 10 were identified, analyzed, and remediated with production-ready code.

---

## 2. Findings Matrix

| # | Vulnerability | Severity | OWASP Top 10 | CWE | Status |
|---|---------------|----------|--------------|-----|--------|
| 1 | SQL Injection in `/login` | **Critical** | A03:2021 - Injection | CWE-89 | Remediated |
| 2 | Plaintext Password Storage | **Critical** | A02:2021 - Cryptographic Failures | CWE-256 | Remediated |
| 3 | Hardcoded Secrets in Source | **High** | A05:2021 - Security Misconfiguration | CWE-798 | Remediated |
| 4 | Reflected XSS in Results | **High** | A03:2021 - Injection | CWE-79 | Remediated |
| 5 | SSRF via URL Checker | **Medium** | A10:2021 - SSRF | CWE-918 | Remediated |
| 6 | Debug Mode in Production | **Medium** | A05:2021 - Security Misconfiguration | CWE-489 | Remediated |
| 7 | Missing CSRF Protection | **Medium** | A01:2021 - Broken Access Control | CWE-352 | Remediated |

---

## 3. Remediation Roadmap
1. **Immediate:** Apply parameterized SQLite queries (`cursor.execute(sql, (param,))`) and scrypt/argon2 hashing for user passwords.
2. **Short Term:** Move `FLASK_SECRET_KEY` to environment variables (`.env`), disable `debug=True`, enable Flask-WTF CSRF protection.
3. **Long Term:** Enforce safe socket address validation against RFC 1918 before outbound HTTP requests, establish automated Bandit CI scanning.
