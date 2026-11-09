"""
Backend API Microservice.
Provides secure data endpoints protected by JWT token verification.
"""

import os
import time
from collections import defaultdict
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import jwt

# Restrict documentation exposure in production
ENABLE_API_DOCS = os.getenv("ENABLE_API_DOCS", "false").lower() == "true"

app = FastAPI(
    title="Backend Microservice",
    version="1.0.0",
    docs_url="/docs" if ENABLE_API_DOCS else None,
    redoc_url="/redoc" if ENABLE_API_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_API_DOCS else None,
)

# Safe CORS Configuration: Disallow wildcard origins with credentials
ALLOWED_ORIGINS = [
    origin.strip()
    for origin in os.getenv(
        "ALLOWED_ORIGINS",
        "http://localhost:8081,http://127.0.0.1:8081,http://localhost:3000,http://127.0.0.1:3000,http://localhost:5173,http://127.0.0.1:5173,http://service-frontend,http://frontend"
    ).split(",")
    if origin.strip()
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "Accept"],
)


@app.middleware("http")
async def add_security_headers_middleware(request: Request, call_next):
    """Enforces defense-in-depth HTTP security headers and prevents banner leakage."""
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-ancestors 'none';"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["X-Permitted-Cross-Domain-Policies"] = "none"
    response.headers["Server"] = "BackendAPI"
    return response

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-jwt-key-2026-secure")
JWT_ALGORITHM = "HS256"
security_bearer = HTTPBearer(auto_error=False)

# Rate Limiting Configuration
RATE_LIMIT_REQUESTS = int(os.getenv("RATE_LIMIT_REQUESTS", "30"))
RATE_LIMIT_WINDOW = int(os.getenv("RATE_LIMIT_WINDOW", "60"))
_rate_limit_records = defaultdict(list)


def rate_limiter(request: Request):
    """Enforces client IP rate limiting on sensitive microservice endpoints."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = time.time()
    cutoff = now - RATE_LIMIT_WINDOW

    # Remove timestamps outside current rate limit window
    timestamps = [t for t in _rate_limit_records[client_ip] if t > cutoff]

    if len(timestamps) >= RATE_LIMIT_REQUESTS:
        retry_after = int(timestamps[0] + RATE_LIMIT_WINDOW - now) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded: maximum {RATE_LIMIT_REQUESTS} requests per {RATE_LIMIT_WINDOW}s.",
            headers={"Retry-After": str(max(1, retry_after))},
        )

    timestamps.append(now)
    _rate_limit_records[client_ip] = timestamps


def verify_jwt_token(credentials: Optional[HTTPAuthorizationCredentials] = Depends(security_bearer)) -> dict:
    """Verifies incoming JWT access token from Authorization header."""
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Bearer token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    token = credentials.credentials
    try:
        payload = jwt.decode(token, JWT_SECRET_KEY, algorithms=[JWT_ALGORITHM])
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authorization token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization token signature",
            headers={"WWW-Authenticate": "Bearer"},
        )


@app.get("/health", tags=["System"])
def health_check():
    """Public health endpoint."""
    return {"status": "ok", "service": "backend-api"}


@app.get("/api/data", tags=["Protected Data"], dependencies=[Depends(rate_limiter)])
def get_secure_data(payload: dict = Depends(verify_jwt_token)):
    """Returns confidential business payload to verified JWT holders."""
    return {
        "status": "success",
        "message": "Confidential telemetry accessed successfully.",
        "authorized_user": payload.get("sub", "unknown"),
        "role": payload.get("role", "member"),
        "timestamp": payload.get("iat", 0),
        "metrics": {
            "node_cpu_utilization": "14.2%",
            "active_secure_channels": 4,
            "firewall_mitigation_level": "optimal"
        }
    }


@app.post("/api/data", tags=["Protected Data"], dependencies=[Depends(rate_limiter)])
def create_secure_record(record: dict, payload: dict = Depends(verify_jwt_token)):
    """Accepts data records when validated with JWT."""
    return {
        "status": "created",
        "created_by": payload.get("sub", "unknown"),
        "payload": record
    }
