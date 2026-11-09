"""
LDAP Authentication Service with TLS (LDAPS) and JWT Issuance.
Authenticates users against OpenLDAP over secure port 636 (TLS)
and generates signed JWT tokens for downstream microservice authorization.
"""

import os
import time
import ssl
from collections import defaultdict
from typing import Optional, List
from fastapi import FastAPI, Depends, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from ldap3 import Server, Connection, Tls, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError
from ldap3.utils.conv import escape_filter_chars
import jwt

# Restrict documentation exposure in production
ENABLE_API_DOCS = os.getenv("ENABLE_API_DOCS", "false").lower() == "true"

app = FastAPI(
    title="LDAP TLS Auth Service",
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
    response.headers["Server"] = "AuthAPI"
    return response

# Configuration
LDAP_HOST = os.getenv("LDAP_HOST", "openldap")
LDAP_PORT = int(os.getenv("LDAP_PORT", "636")) # Secure LDAPS Port
LDAP_USE_SSL = os.getenv("LDAP_USE_SSL", "true").lower() == "true"
LDAP_BASE_DN = os.getenv("LDAP_BASE_DN", "dc=example,dc=com")
LDAP_ADMIN_DN = os.getenv("LDAP_ADMIN_DN", "cn=admin,dc=example,dc=com")
LDAP_ADMIN_PASSWORD = os.getenv("LDAP_ADMIN_PASSWORD", "adminpassword")

JWT_SECRET_KEY = os.getenv("JWT_SECRET_KEY", "super-secret-jwt-key-2026-secure")
JWT_ALGORITHM = "HS256"
JWT_EXPIRATION_SECONDS = 3600

# Rate Limiting Configuration for Authentication
AUTH_RATE_LIMIT_REQUESTS = int(os.getenv("AUTH_RATE_LIMIT_REQUESTS", "15"))
AUTH_RATE_LIMIT_WINDOW = int(os.getenv("AUTH_RATE_LIMIT_WINDOW", "60"))
_login_rate_limit_records = defaultdict(list)


def login_rate_limiter(request: Request):
    """Enforces client IP rate limiting on login endpoint to mitigate brute-force attacks."""
    client_ip = request.client.host if request.client else "127.0.0.1"
    now = time.time()
    cutoff = now - AUTH_RATE_LIMIT_WINDOW

    timestamps = [t for t in _login_rate_limit_records[client_ip] if t > cutoff]
    if len(timestamps) >= AUTH_RATE_LIMIT_REQUESTS:
        retry_after = int(timestamps[0] + AUTH_RATE_LIMIT_WINDOW - now) + 1
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Too many authentication attempts. Please retry after {retry_after}s.",
            headers={"Retry-After": str(max(1, retry_after))},
        )
    timestamps.append(now)
    _login_rate_limit_records[client_ip] = timestamps


class LoginRequest(BaseModel):
    username: str
    password: str


class UserProfile(BaseModel):
    username: str
    dn: str
    full_name: Optional[str] = None
    email: Optional[str] = None
    groups: List[str] = []


class AuthTokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: UserProfile


def get_ldap_server() -> Server:
    """Configures secure LDAP server connection using TLS."""
    tls_config = Tls(validate=ssl.CERT_NONE)
    return Server(
        host=LDAP_HOST,
        port=LDAP_PORT,
        use_ssl=LDAP_USE_SSL,
        tls=tls_config if LDAP_USE_SSL else None,
        get_info=ALL,
        connect_timeout=5,
    )


def authenticate_ldap_user(username: str, password: str) -> Optional[UserProfile]:
    """Search-then-Bind authentication against LDAPS."""
    server = get_ldap_server()
    sanitized_user = escape_filter_chars(username.strip())
    search_base = f"ou=users,{LDAP_BASE_DN}"
    search_filter = f"(&(objectClass=inetOrgPerson)(uid={sanitized_user}))"

    # Step 1: Admin bind over TLS
    with Connection(
        server,
        user=LDAP_ADMIN_DN,
        password=LDAP_ADMIN_PASSWORD,
        auto_bind=True,
        receive_timeout=5,
    ) as admin_conn:
        admin_conn.search(
            search_base=search_base,
            search_filter=search_filter,
            search_scope=SUBTREE,
            attributes=["cn", "mail", "displayName", "uid"],
        )

        if not admin_conn.entries:
            return None

        entry = admin_conn.entries[0]
        user_dn = entry.entry_dn
        full_name = str(getattr(entry, "displayName", entry.cn))
        email = str(getattr(entry, "mail", ""))

        # Query groups
        groups_base = f"ou=groups,{LDAP_BASE_DN}"
        escaped_dn = escape_filter_chars(user_dn)
        admin_conn.search(
            search_base=groups_base,
            search_filter=f"(&(objectClass=groupOfNames)(member={escaped_dn}))",
            search_scope=SUBTREE,
            attributes=["cn"],
        )
        groups = [str(g.cn.value) for g in admin_conn.entries if hasattr(g, "cn")]

    # Step 2: Bind as the user over TLS
    with Connection(
        server,
        user=user_dn,
        password=password,
        auto_bind=False,
        receive_timeout=5,
    ) as user_conn:
        if not user_conn.bind():
            return None

    return UserProfile(
        username=username,
        dn=user_dn,
        full_name=full_name,
        email=email,
        groups=groups,
    )


@app.get("/health", tags=["Monitoring"])
def health_check():
    """Verify service and LDAPS connectivity status."""
    try:
        server = get_ldap_server()
        with Connection(
            server,
            user=LDAP_ADMIN_DN,
            password=LDAP_ADMIN_PASSWORD,
            auto_bind=True,
            receive_timeout=5,
        ) as conn:
            is_bound = conn.bound
    except Exception:
        is_bound = False

    return {
        "status": "ok" if is_bound else "degraded",
        "service": "ldap-tls-auth",
        "port": LDAP_PORT,
        "tls_active": LDAP_USE_SSL,
        "ldap_connected": is_bound
    }


@app.post("/login", response_model=AuthTokenResponse, tags=["Authentication"], dependencies=[Depends(login_rate_limiter)])
def login(creds: LoginRequest):
    """
    Authenticates user credentials against OpenLDAP via LDAPS (port 636)
    and returns a signed JWT access token.
    Enforces authentication by strictly rejecting empty credentials / anonymous binds.
    """
    if not creds.username or not creds.username.strip() or not creds.password or not creds.password.strip():
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username and password are required. Anonymous binding is prohibited.",
        )

    try:
        profile = authenticate_ldap_user(creds.username, creds.password)
    except LDAPSocketOpenError:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Secure LDAPS directory server is unreachable",
        )
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Directory error during authentication: {str(exc)}",
        )

    if profile is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Issue JWT Token
    now = int(time.time())
    payload = {
        "sub": profile.username,
        "dn": profile.dn,
        "role": profile.groups[0] if profile.groups else "user",
        "groups": profile.groups,
        "iat": now,
        "exp": now + JWT_EXPIRATION_SECONDS,
    }
    token = jwt.encode(payload, JWT_SECRET_KEY, algorithm=JWT_ALGORITHM)

    return AuthTokenResponse(
        access_token=token,
        token_type="bearer",
        user=profile,
    )
