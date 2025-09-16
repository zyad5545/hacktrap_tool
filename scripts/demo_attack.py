import argparse
import requests

def brute_force(target):
    users = ["admin", "root", "test"]
    passwords = ["1234", "123456", "password"]
    for user in users:
        for password in passwords:
            try:
                resp = requests.post(
                    f"{target}/login",
                    json={"username": user, "password": password},
                    headers={"Content-Type": "application/json"}
                )
                print(f"Attempt {user}:{password} -> {resp.status_code} {resp.text}")
            except Exception as e:
                print(f"Attempt {user}:{password} error -> {e}")

def honeypot(target):
    try:
        resp = requests.post(
            f"{target}/honeypot",
            json={"trap": "fake_command", "attacker": "simulated"},
            headers={"Content-Type": "application/json"}
        )
        print("Honeypot post ->", resp.status_code, resp.text)
    except Exception as e:
        print("Honeypot error ->", e)

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="Target backend URL")
    parser.add_argument("--type", default="all", help="Attack type: brute, honeypot, all")
    args = parser.parse_args()

    if args.type in ["brute", "all"]:
        print(f"Simulating brute force against {args.target}/login")
        brute_force(args.target)

    if args.type in ["honeypot", "all"]:
        honeypot(args.target)