"""
LDAP Authentication Service with TLS (LDAPS) and JWT Issuance.
Authenticates users against OpenLDAP over secure port 636 (TLS)
and generates signed JWT tokens for downstream microservice authorization.
"""

import os
import time
import ssl
from typing import Optional, List
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from ldap3 import Server, Connection, Tls, ALL, SUBTREE
from ldap3.core.exceptions import LDAPException, LDAPSocketOpenError
from ldap3.utils.conv import escape_filter_chars
import jwt

app = FastAPI(title="LDAP TLS Auth Service", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

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


@app.post("/login", response_model=AuthTokenResponse, tags=["Authentication"])
def login(creds: LoginRequest):
    """
    Authenticates user credentials against OpenLDAP via LDAPS (port 636)
    and returns a signed JWT access token.
    """
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
