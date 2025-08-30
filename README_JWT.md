# JWT Security Task — PoC & Instructions

## What this shows
- **Weak-secret brute-force (HS256)**: If a JWT is signed with a guessable secret (e.g., `secret`, `password`), an attacker can recover the secret and **forge admin tokens**.
- **`alg=none` PoC**: Constructs an **unsigned** token. This only bypasses auth if a **misconfigured server** accepts `alg=none` (modern libs reject it by default).

## Requirements
- Python 3.9+
- Install: `pip install pyjwt`

## Run
```bash
python jwt_attack_demo.py --demo weaksecret
python jwt_attack_demo.py --demo none
```

## Expected output (weaksecret)
- Generates a victim token signed with a weak secret
- Brute-forces the secret from a tiny wordlist
- Forges an admin token and decodes it successfully

## Notes
- Use a **strong, high-entropy secret** or switch to **RS256** with key pairs.
- Always **disable `alg=none`** and enforce allowed algorithms explicitly.
- Enforce **short expirations**, **aud/iss** claims, and **token revocation** where possible.
