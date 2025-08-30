# secure_api.py
"""
FastAPI-based secure API implementing:
  - POST /register (bcrypt password hashing)
  - POST /login (issue JWT)
  - GET /profile (protected by JWT)
Security:
  - HS256 signing with a strong secret
  - 15-minute access token expiry
  - Input validation with Pydantic
Run:
  pip install fastapi uvicorn pyjwt bcrypt passlib[bcrypt] python-multipart
  uvicorn secure_api:app --reload
Test (example):
  1) Register:
     curl -s -X POST http://127.0.0.1:8000/register -H "Content-Type: application/json" \
       -d '{"username":"preet","password":"StrongPass123!"}'
  2) Login (get token):
     curl -s -X POST http://127.0.0.1:8000/login -H "Content-Type: application/json" \
       -d '{"username":"preet","password":"StrongPass123!"}'
  3) Access profile:
     curl -s http://127.0.0.1:8000/profile -H "Authorization: Bearer <JWT>"
"""
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict
from fastapi import FastAPI, HTTPException, Depends, Header
from pydantic import BaseModel, Field
from passlib.context import CryptContext
import jwt  # PyJWT
import os

app = FastAPI(title="Secure API (JWT)")

# In-memory user "db" for demo purposes
USERS: Dict[str, str] = {}  # username -> password_hash
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# Load secret from env or fallback (for demo). In production, NEVER hardcode and use >=32B random.
JWT_SECRET = os.getenv("JWT_SECRET", "change-this-to-a-long-random-secret-value-please")
JWT_ALG = "HS256"
ACCESS_MINUTES = 15

class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=32, pattern=r"^[a-zA-Z0-9_]+$")
    password: str = Field(min_length=8, max_length=128)

class TokenOut(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class ProfileOut(BaseModel):
    username: str

def create_access_token(sub: str) -> str:
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": sub,
        "iat": int(now.timestamp()),
        "nbf": int(now.timestamp()),
        "exp": int((now + timedelta(minutes=ACCESS_MINUTES)).timestamp()),
        "iss": "secure-api-demo",
        "aud": "secure-api-clients"
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def verify_token(auth_header: Optional[str]) -> str:
    if not auth_header or not auth_header.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Missing or invalid Authorization header")
    token = auth_header.split(" ", 1)[1].strip()
    try:
        payload = jwt.decode(
            token,
            JWT_SECRET,
            algorithms=[JWT_ALG],
            audience="secure-api-clients",
            issuer="secure-api-demo"
        )
        return payload["sub"]
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="Token expired")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid token")

@app.post("/register")
def register(body: RegisterIn):
    if body.username in USERS:
        raise HTTPException(status_code=400, detail="Username already exists")
    password_hash = pwd_context.hash(body.password)
    USERS[body.username] = password_hash
    return {"message": "registered"}

@app.post("/login", response_model=TokenOut)
def login(body: RegisterIn):
    if body.username not in USERS:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not pwd_context.verify(body.password, USERS[body.username]):
        raise HTTPException(status_code=401, detail="Invalid credentials")
    token = create_access_token(body.username)
    return TokenOut(access_token=token, expires_in=ACCESS_MINUTES * 60)

@app.get("/profile", response_model=ProfileOut)
def profile(Authorization: Optional[str] = Header(None)):
    username = verify_token(Authorization)
    return ProfileOut(username=username)
