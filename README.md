# CTF Internship Assignment – JWT Security & Secure API

This repository contains my submission for the DGPL CTF Development Internship Assignment (due August 30, 2025).  

It includes:
- **Task 1: JWT Security Research & PoC**
- **Task 2: Secure API Implementation**

---

## 📌 Task 1: JWT Security Research & PoC

### Files
- `jwt_attack_demo.py` → Python PoC demonstrating:
  - **Weak-secret brute-force (HS256)**
  - **`alg=none` token construction**
- `jwt_research_report.pdf` → 1–2 page research report on JWT vulnerabilities and mitigations.

### Requirements
```bash
pip install -r requirements.txt

Run the demos
# Weak secret brute-force attack
python jwt_attack_demo.py --demo weaksecret

# alg=none attack PoC
python jwt_attack_demo.py --demo none
Expected Results

For weak secret attack:

Generates a victim token signed with "secret".

Brute-forces the secret from a small wordlist.

Forges a new token with role=admin.

For alg=none attack:

Constructs an unsigned token.

⚠️ Note: This only works if a vulnerable server accepts alg=none. Modern libraries reject it.

📌 Task 2: Secure API Implementation

Implemented with FastAPI (Python).

Files

secure_api.py → API implementation

Endpoints:

POST /register → Register user (bcrypt password hashing)

POST /login → Authenticate + issue JWT (HS256, 15-min expiry)

GET /profile → Protected route requiring valid JWT

Setup
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
pip install -r requirements.txt

Run
uvicorn secure_api:app --reload

Test with curl
# 1) Register
curl -X POST http://127.0.0.1:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"preet","password":"StrongPass123!"}'

# 2) Login (get JWT)
curl -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"preet","password":"StrongPass123!"}'

# 3) Access protected profile
curl http://127.0.0.1:8000/profile \
  -H "Authorization: Bearer <PASTE_JWT_HERE>"

🔒 Security Features Implemented

Strong secret for HS256 (≥ 32 random bytes).

Token expiry set to 15 minutes.

Validates standard claims: iss, aud, exp, nbf, iat.

Passwords stored with bcrypt hashing.

Proper input validation via Pydantic.

Recommend HTTPS + HttpOnly cookies for production.

📚 References

OWASP JWT Cheat Sheet

NIST NVD (real-world CVEs related to JWT)

