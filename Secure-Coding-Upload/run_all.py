import os
import sys
import time
import subprocess
import signal

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def get_python_exe():
    # Prefer virtual environment python if available
    venv_py = os.path.join(BASE_DIR, "secure_app", "venv", "Scripts", "python.exe")
    if os.path.exists(venv_py):
        return venv_py
    return sys.executable

PYTHON_EXE = get_python_exe()

def banner(title):
    print("\n" + "=" * 70)
    print(f"  {title}")
    print("=" * 70)

def run_tests():
    banner("1. RUNNING SECURITY REGRESSION TESTS (PYTEST)")
    cmd = [PYTHON_EXE, "-m", "pytest", os.path.join(BASE_DIR, "tests", "test_security.py"), "-v"]
    res = subprocess.run(cmd, cwd=BASE_DIR)
    return res.returncode == 0

def run_bandit():
    banner("2. RUNNING STATIC APPLICATION SECURITY TESTING (BANDIT)")
    try:
        # Check if bandit is installed
        res = subprocess.run([PYTHON_EXE, "-m", "bandit", "--version"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if res.returncode != 0:
            print("[*] Installing bandit...")
            subprocess.run([PYTHON_EXE, "-m", "pip", "install", "bandit", "-q"])
        
        print("\n--> [A] Scanning vulnerable_app/app.py (Known vulnerabilities present):")
        subprocess.run([PYTHON_EXE, "-m", "bandit", os.path.join(BASE_DIR, "vulnerable_app", "app.py"), "-ll"], cwd=BASE_DIR)

        print("\n--> [B] Scanning secure_app/app.py (Remediated codebase):")
        subprocess.run([PYTHON_EXE, "-m", "bandit", os.path.join(BASE_DIR, "secure_app", "app.py"), "-ll"], cwd=BASE_DIR)
        return True
    except Exception as e:
        print(f"[-] Bandit scan skipped: {e}")
        return False

def test_exploits():
    banner("3. DEMONSTRATING EXPLOIT PROOF-OF-CONCEPTS")
    print("[*] Temporarily starting vulnerable_app on port 5000...")
    
    proc = subprocess.Popen(
        [PYTHON_EXE, "app.py"],
        cwd=os.path.join(BASE_DIR, "vulnerable_app"),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    
    time.sleep(2)
    
    try:
        print("\n--- [PoC 1: SQL Injection Auth Bypass] ---")
        subprocess.run([PYTHON_EXE, os.path.join(BASE_DIR, "exploits", "exploit_sqli.py")], cwd=BASE_DIR)
        
        print("\n--- [PoC 2: Reflected Cross-Site Scripting (XSS)] ---")
        subprocess.run([PYTHON_EXE, os.path.join(BASE_DIR, "exploits", "exploit_xss.py")], cwd=BASE_DIR)
        
        print("\n--- [PoC 3: Server-Side Request Forgery (SSRF)] ---")
        subprocess.run([PYTHON_EXE, os.path.join(BASE_DIR, "exploits", "exploit_ssrf.py")], cwd=BASE_DIR)
    finally:
        print("\n[*] Stopping temporary background test server...")
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()

def start_both_apps():
    banner("4. RUNNING BOTH APPLICATIONS SIMULTaneously")
    print("  [1] Vulnerable App: http://127.0.0.1:5000")
    print("      Username: admin | Password: Admin@123")
    print("")
    print("  [2] Hardened Secure App: http://127.0.0.1:5001")
    print("      Username: admin | Password: Admin@Secure2026!")
    print("")
    print("  -> Press CTRL+C anytime in this window to stop both servers.")
    print("=" * 70)

    # Start vulnerable app on port 5000
    p_vuln = subprocess.Popen(
        [PYTHON_EXE, "app.py"],
        cwd=os.path.join(BASE_DIR, "vulnerable_app")
    )

    # Start secure app on port 5001
    p_sec = subprocess.Popen(
        [PYTHON_EXE, "app.py"],
        cwd=os.path.join(BASE_DIR, "secure_app")
    )

    try:
        while True:
            time.sleep(1)
            if p_vuln.poll() is not None or p_sec.poll() is not None:
                break
    except KeyboardInterrupt:
        print("\n[*] Shutting down both applications...")
    finally:
        p_vuln.terminate()
        p_sec.terminate()
        try:
            p_vuln.wait(timeout=2)
            p_sec.wait(timeout=2)
        except Exception:
            p_vuln.kill()
            p_sec.kill()
        print("[*] Both applications stopped.")

def main():
    print("""
======================================================================
     CodeAlpha Task 3: Secure Coding Suite Master Runner
======================================================================
  [1] Run All Verification (Pytest Tests + Bandit SAST + Exploits)
  [2] Start BOTH Applications (Port 5000 & Port 5001)
  [3] Run Full Suite + Then Start Both Applications
======================================================================
    """)
    
    # Non-interactive mode support
    if "--both" in sys.argv:
        start_both_apps()
        return
    elif "--verify" in sys.argv or "--no-prompt" in sys.argv:
        run_tests()
        run_bandit()
        test_exploits()
        return

    choice = input("Select an option [default: 3]: ").strip()
    if choice == "1":
        run_tests()
        run_bandit()
        test_exploits()
    elif choice == "2":
        start_both_apps()
    else:
        run_tests()
        run_bandit()
        test_exploits()
        start_both_apps()

if __name__ == "__main__":
    main()
