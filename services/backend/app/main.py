"""
Backend API Microservice.
Provides secure data endpoints protected by JWT token verification.
"""

import os
from typing import Optional
from fastapi import FastAPI, Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
import jwt

app = FastAPI(title="Backend Microservice", version="1.0.0")

# CORS setup
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-jwt-key-2026-secure")
JWT_ALGORITHM = "HS256"
security_bearer = HTTPBearer(auto_error=False)


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


@app.get("/api/data", tags=["Protected Data"])
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


@app.post("/api/data", tags=["Protected Data"])
def create_secure_record(record: dict, payload: dict = Depends(verify_jwt_token)):
    """Accepts data records when validated with JWT."""
    return {
        "status": "created",
        "created_by": payload.get("sub", "unknown"),
        "payload": record
    }
