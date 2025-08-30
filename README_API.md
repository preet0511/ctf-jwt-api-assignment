# Secure API Task — FastAPI Implementation

Implements:
- `POST /register` — registers user with **bcrypt** password hashing.
- `POST /login` — verifies credentials and issues **HS256 JWT** with 15-minute expiry.
- `GET /profile` — protected endpoint requiring a valid JWT in `Authorization: Bearer <token>`.

## Setup
```bash
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate
pip install fastapi uvicorn pyjwt bcrypt passlib[bcrypt] python-multipart
export JWT_SECRET="$(python - <<'PY'\nimport secrets; print(secrets.token_urlsafe(64))\nPY)"
```

## Run
```bash
uvicorn secure_api:app --reload
```

## Test with curl
```bash
# 1) Register
curl -s -X POST http://127.0.0.1:8000/register \
  -H "Content-Type: application/json" \
  -d '{"username":"preet","password":"StrongPass123!"}'

# 2) Login
curl -s -X POST http://127.0.0.1:8000/login \
  -H "Content-Type: application/json" \
  -d '{"username":"preet","password":"StrongPass123!"}'

# 3) Use the token to access /profile
curl -s http://127.0.0.1:8000/profile -H "Authorization: Bearer <PASTE_JWT_HERE>"
```

## Security Notes
- Use a **strong, random** `JWT_SECRET` (≥ 32 bytes). Rotate periodically.
- Pin algorithm to **HS256** (or switch to **RS256** with keypairs).
- Validate `aud`, `iss`, `exp`, `nbf`, `iat` (implemented).
- Prefer HttpOnly, Secure cookies if used in browsers.
- Always use HTTPS in production.
