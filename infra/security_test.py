#!/usr/bin/env python3
"""
=============================================================================
 ZERO-TRUST API GATEWAY — SECURITY TEST SUITE (Rút gọn theo SecurityTestReport.docx)
=============================================================================
"""

import requests
import urllib3
import jwt as pyjwt
import time
import sys
import os
import tempfile
import subprocess
import shutil
from pathlib import Path
from datetime import datetime

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ----------------------------- Đường dẫn certs ---------------------------------
def _find_certs_dir() -> Path:
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir / "certs",
        script_dir.parent / "infra" / "certs",
        script_dir.parent / "certs",
        script_dir / ".." / "infra" / "certs",
    ]
    for path in candidates:
        resolved = path.resolve()
        if resolved.exists() and (resolved / "root-ca.crt").exists():
            return resolved
    print(f"\n⚠ Không tìm thấy certs/ - hãy chạy bash infra/setup.sh")
    return script_dir.parent / "infra" / "certs"

CERTS_DIR = _find_certs_dir()
ENVOY_URL = "https://127.0.0.1:443"
CERT_FILE = str(CERTS_DIR / "client.crt")
KEY_FILE  = str(CERTS_DIR / "client.key")
CA_FILE   = str(CERTS_DIR / "root-ca.crt")

# ----------------------------- Màu sắc terminal ---------------------------------
GREEN  = "\033[92m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

results = []

# ----------------------------- Helper functions ---------------------------------
def _make_request(method, path, headers=None, cert=None):
    url = ENVOY_URL + path
    try:
        resp = requests.request(method, url, headers=headers or {}, cert=cert, verify=False, timeout=5)
        return resp
    except requests.exceptions.SSLError as e:
        return _MockResponse(403, {"error": f"TLS Handshake Failed: {str(e)[:80]}"})
    except requests.exceptions.ConnectionError as e:
        return _MockResponse(503, {"error": f"Connection refused: {str(e)[:80]}"})

class _MockResponse:
    def __init__(self, status_code, data):
        self.status_code = status_code
        self._data = data
    def json(self):
        return self._data

def _get_valid_jwt():
    print(f"\n[DEBUG] Cert dir: {CERTS_DIR}")
    if not os.path.exists(CERT_FILE) or not os.path.exists(KEY_FILE):
        print("[ERROR] Client cert missing. Run bash infra/setup.sh")
        return None
    try:
        resp = requests.post(ENVOY_URL + "/auth/login", cert=(CERT_FILE, KEY_FILE), verify=False, timeout=5)
        if resp.status_code == 200:
            token = resp.json().get("access_token")
            if token:
                print(f"\n{'='*60}\n{YELLOW}[JWT ACCESS TOKEN]{RESET}\n{'='*60}\n{token}\n{'='*60}\n")
                return token
            else:
                print("[ERROR] No access_token in response")
        else:
            print(f"[ERROR] Login failed: {resp.status_code} - {resp.text}")
    except Exception as e:
        print(f"[ERROR] {e}")
    return None

def _forge_invalid_jwt_rs256():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    fake_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = fake_key.private_bytes(encoding=serialization.Encoding.PEM,
                                 format=serialization.PrivateFormat.TraditionalOpenSSL,
                                 encryption_algorithm=serialization.NoEncryption())
    now = int(time.time())
    payload = {
        "iss": "https://auth.zero-trust.local",
        "sub": "attacker",
        "aud": "https://api.resource.local",
        "exp": now + 3600,
        "scope": "read:resources",
        "cnf": {"x5t#S256": "FAKE_THUMBPRINT"}
    }
    return pyjwt.encode(payload, pem, algorithm="RS256")

def _expired_jwt():
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    fake_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = fake_key.private_bytes(encoding=serialization.Encoding.PEM,
                                 format=serialization.PrivateFormat.TraditionalOpenSSL,
                                 encryption_algorithm=serialization.NoEncryption())
    now = int(time.time())
    payload = {
        "iss": "https://auth.zero-trust.local",
        "sub": "test",
        "aud": "https://api.resource.local",
        "exp": now - 7200,
        "iat": now - 10800,
        "cnf": {"x5t#S256": "some-thumbprint"}
    }
    return pyjwt.encode(payload, pem, algorithm="RS256")

def _print_result(tc_id, name, threat_ref, expected, response, passed):
    status = f"{GREEN}✅ PASS{RESET}" if passed else f"{RED}❌ FAIL{RESET}"
    print(f"\n{'─'*65}")
    print(f"{BOLD}[{tc_id}] {name}{RESET}")
    print(f"  Threat Model Ref : {CYAN}{threat_ref}{RESET}")
    print(f"  Expected         : {expected}")
    print(f"  Got              : HTTP {response.status_code} → {_safe_json(response)}")
    print(f"  Result           : {status}")
    results.append({"id": tc_id, "name": name, "passed": passed})

def _safe_json(resp):
    try:
        return resp.json()
    except:
        return "(non-JSON response)"

# ----------------------------- Test cases --------------------------------------
def tc01_valid_request():
    print(f"\n{'═'*65}\n{BOLD}{CYAN}TC-01: VALID REQUEST — Luồng hợp lệ hoàn chỉnh{RESET}")
    token = _get_valid_jwt()
    if not token:
        results.append({"id": "TC-01", "name": "Valid Request", "passed": False})
        return
    resp = _make_request("GET", "/api/protected", headers={"Authorization": f"Bearer {token}"}, cert=(CERT_FILE, KEY_FILE))
    passed = (resp.status_code == 200)
    _print_result("TC-01", "Valid Request", "N/A (Happy Path)", "HTTP 200 OK", resp, passed)

def tc02_invalid_jwt_signature():
    print(f"\n{'═'*65}\n{BOLD}{CYAN}TC-02: INVALID JWT SIGNATURE — Forged token (RS256 wrong key){RESET}")
    forged = _forge_invalid_jwt_rs256()
    print(f"\n[FORGED JWT] {forged}\n")
    resp = _make_request("GET", "/api/protected", headers={"Authorization": f"Bearer {forged}"}, cert=(CERT_FILE, KEY_FILE))
    passed = (resp.status_code == 403)
    _print_result("TC-02", "Invalid JWT Signature", "Threat 4.5 — Privilege Escalation", "HTTP 403 Forbidden", resp, passed)

def tc03_self_signed_cert():
    print(f"\n{'═'*65}\n{BOLD}{CYAN}TC-03: SELF-SIGNED CERTIFICATE — Impersonation (mTLS){RESET}")
    attacker_cert = CERTS_DIR / "attacker_selfsigned.crt"
    attacker_key = CERTS_DIR / "attacker_selfsigned.key"
    if attacker_cert.exists(): attacker_cert.unlink()
    if attacker_key.exists(): attacker_key.unlink()
    subj = "/CN=attacker-self-signed"
    cmd = f'openssl req -x509 -newkey rsa:2048 -nodes -keyout {attacker_key} -out {attacker_cert} -days 1 -subj "{subj}"'
    subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print(f"\n[SELF-SIGNED CERT] {attacker_cert}")
    print(f"[SELF-SIGNED KEY]  {attacker_key}")
    result = subprocess.run(f'openssl x509 -in {attacker_cert} -noout -subject -issuer', shell=True, capture_output=True, text=True)
    print(result.stdout)
    print("[INFO] Self-signed → không được Envoy trust → TLS handshake fail.\n")
    resp = _make_request("GET", "/api/protected", headers={"Authorization": "Bearer dummy"}, cert=(str(attacker_cert), str(attacker_key)))
    passed = (resp.status_code in (401, 403))
    _print_result("TC-03", "Self-Signed Certificate", "Threat 4.3 — Impersonation", "TLS Handshake FAIL", resp, passed)

def tc04_replay_attack():
    print(f"\n{'═'*65}\n{BOLD}{CYAN}TC-04: REPLAY ATTACK — Expired token replayed{RESET}")
    print(f"  Threat Model Ref : {CYAN}Threat 4.2 + Residual Risk §5 (no replay cache){RESET}")
    print(f"  {YELLOW}⚠ Residual risk: Token còn hạn + cert lộ có thể replay đến hết exp{RESET}")
    expired = _expired_jwt()
    all_pass = True
    last_resp = None
    for i in range(1,4):
        resp = _make_request("GET", "/api/protected", headers={"Authorization": f"Bearer {expired}"}, cert=(CERT_FILE, KEY_FILE))
        last_resp = resp
        print(f"  Attempt {i} → HTTP {resp.status_code}")
        if resp.status_code != 403:
            all_pass = False
    passed = all_pass
    _print_result("TC-04", "Replay Attack (Expired Token)", "Threat 4.2 + Residual Risk §5", "HTTP 403 Forbidden (all attempts)", last_resp, passed)

# ----------------------------- Main --------------------------------------------
def print_summary():
    total = len(results)
    passed = sum(1 for r in results if r["passed"])
    failed = total - passed
    print(f"\n{'═'*65}\n{BOLD}📊 KẾT QUẢ KIỂM THỬ BẢO MẬT{RESET}\n{'═'*65}")
    print(f"  Tổng số test case : {total}")
    print(f"  Passed            : {GREEN}{passed}{RESET}")
    print(f"  Failed            : {RED}{failed}{RESET}")
    print(f"{'─'*65}")
    for r in results:
        icon = f"{GREEN}✅{RESET}" if r["passed"] else f"{RED}❌{RESET}"
        print(f"  {icon}  {r['id']} — {r['name']}")
    print(f"{'═'*65}")
    if failed > 0:
        print(f"\n{YELLOW}⚠ Một số test FAIL:{RESET}")
        print("   - TC-02: Resource API chưa xác thực chữ ký JWT (cần bổ sung verify RS256)")
        print("   - TC-04: Resource API chưa kiểm tra exp claim")
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    print(f"{BOLD}{'═'*65}{RESET}")
    print(f"{BOLD}{CYAN} ZERO-TRUST SECURITY TEST SUITE (RÚT GỌN){RESET}")
    print(f"{BOLD} Thời gian: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{RESET}")
    print(f"{BOLD}{'═'*65}{RESET}")
    tc01_valid_request()
    tc02_invalid_jwt_signature()
    tc03_self_signed_cert()
    tc04_replay_attack()
    sys.exit(print_summary())