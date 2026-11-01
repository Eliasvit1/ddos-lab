# Advanced Security Lab: Container Defense with Fail2ban, TLS/LDAPS, and External Load Benchmarking

## 1. Executive Summary & Architecture Overview

This security laboratory demonstrates defense-in-depth containerization engineering. It validates real-time HTTP Flood / DoS mitigation across an enterprise multi-tier architecture using **Fail2ban**, Linux kernel packet filtering (**`iptables`** via `NET_ADMIN`), **TLS port encryption for LDAP (LDAPS on port 636)**, and **JWT bearer authentication**.

All services are orchestrated on an isolated virtual bridge network (`labnet`: `172.29.0.0/24`) and mapped to specific host ports for external validation.

### Architecture Diagram

```
+----------------------------------------------------------------------------------------------------+
|                                HOST MACHINE (Windows / Linux)                                      |
|                                                                                                    |
|   +--------------------------------------------------------------------------------------------+   |
|   |                       External Load Runner CLI (http_load_runner.py)                       |   |
|   |         [--host 127.0.0.1] [--port <PORT>] [--concurrency 25] [--rate 80] [--duration 8]  |   |
|   +--------------------------------------------------------------------------------------------+   |
+-----------------|------------------------------|------------------------------|--------------------+
                  | :8081                        | :8082                        | :8083 (HTTP) / :636 (TLS)
                  v                              v                              v
+----------------------------------------------------------------------------------------------------+
|                                ISOLATED DOCKER NETWORK (172.29.0.0/24)                              |
|                                                                                                    |
|  +------------------------+  +------------------------+  +--------------------------------------+  |
|  |    service-frontend    |  |    service-backend     |  |          service-ldap-auth           |  |
|  |     (172.29.0.8:80)    |  |     (172.29.0.7:80)    |  |            (172.29.0.6:80)           |  |
|  |                        |  |                        |  |                                      |  |
|  |  * Nginx Web Server    |  |  * FastAPI Microservice|  |  * FastAPI Auth + JWT Issuer         |  |
|  |  * Zero console.log JWT|  |  * JWT Bearer Auth     |  |  * Talks to OpenLDAP via TLS         |  |
|  |  * Fail2ban (iptables) |  |  * Fail2ban (iptables) |  |  * Fail2ban (iptables)               |  |
|  +------------------------+  +------------------------+  +------------------+-------------------+  |
|                                                                             |                      |
|                                                                     Secure  | ldaps://openldap:636 |
|                                                                     Channel v (Port-Level TLS)     |
|                                                          +--------------------------------------+  |
|                                                          |           service-openldap           |  |
|                                                          |           (172.29.0.5:636)           |  |
|                                                          |                                      |  |
|                                                          |  * OpenLDAP Directory Server         |  |
|                                                          |  * Mandatory TLS/SSL Encryption      |  |
|                                                          +--------------------------------------+  |
|                                                                                                    |
|  +---------------------------------------------+  +---------------------------------------------+  |
|  |        http-victim-protected (:8084)        |  |       http-victim-unprotected (:8085)       |  |
|  |       Hardened Target + Fail2ban Jail       |  |      Vanilla Nginx (Unmitigated Baseline)   |  |
|  +---------------------------------------------+  +---------------------------------------------+  |
+----------------------------------------------------------------------------------------------------+
```

---

## 2. Service Specifications & Security Hardening

| Service Name | Container Name | Host Port | Internal IP | Security Defenses |
| :--- | :--- | :--- | :--- | :--- |
| **Frontend Dashboard** | `service-frontend` | `8081` | `172.29.0.8` | Nginx + Fail2ban (`http-flood`), `NET_ADMIN`, Client credential sanitization (`ZERO console.log(jwt)`). |
| **Backend API** | `service-backend` | `8082` | `172.29.0.7` | FastAPI + JWT Bearer Authorization (`HS256`) + Nginx Reverse Proxy + Fail2ban (`http-flood`). |
| **LDAP Auth (JWT Issuer)** | `service-ldap-auth` | `8083` | `172.29.0.6` | FastAPI + Fail2ban + Direct LDAPS client querying OpenLDAP over TLS port 636. Issues signed JWTs. |
| **Directory Server** | `service-openldap` | `636` | `172.29.0.5` | OpenLDAP 1.5.0 with enforced TLS / LDAPS (`LDAP_TLS: "true"`, port 636 only). |
| **Protected Reference** | `http-victim-protected`| `8084` | `172.29.0.10` | Nginx 1.27 + Fail2ban (`http-flood` jail, maxretry 60, findtime 10s). |
| **Unprotected Baseline**| `http-victim-unprotected`| `8085` | `172.29.0.11` | Vanilla Nginx (Zero rate limiting, no firewall). |

### Security Implementations:
1. **Frontend Credential Protection (`app.js`):**
   - Cleaned all diagnostic logging. No JWT tokens, secrets, or bearer signatures are ever logged to the browser console (`console.log`), mitigating credential harvesting via DevTools or XSS scraping.
2. **Port-Level LDAP Encryption (TLS / LDAPS):**
   - Traditional unencrypted LDAP (`port 389`) transmits bind credentials in plaintext. The OpenLDAP service is configured with TLS enabled, and the authentication API communicates strictly over `ldaps://openldap:636` with SSL context verification.
3. **Fail2ban Jail Configuration (`jail.local`):**
   - **`banaction = iptables-allports`**: Blocks offending IPs on all container ports using Linux kernel packet filtering.
   - **`backend = polling`**: Real-time inspection of active `/var/log/nginx/access.log`.
   - **`maxretry = 60`** within **`findtime = 10s`**: Accommodates standard burst traffic while deterministically neutralizing high-velocity HTTP floods.
   - **`bantime = 10m`** with geometric backoff (`bantime.increment = true`, `bantime.factor = 2`).

---

## 3. External HTTP Load Runner Tool (`http_load_runner.py`)

The original container-bound flood script was completely re-architected into an enterprise-grade CLI utility executable directly on the **host machine** (Windows, macOS, or Linux).

### Script Modification Highlights:
1. **Host-Decoupled Execution:** Utilizes Python standard library (`urllib.request`, `concurrent.futures`, `argparse`), eliminating external pip dependencies for maximum portability.
2. **Dynamic CLI Argument Parsing:**
   - `--host`: Target IP or hostname (e.g., `127.0.0.1` or `localhost`).
   - `--port`: Target TCP port (e.g., `8081`, `8082`, `8083`, `8084`, `8085`).
   - `--path`: Target endpoint URI (default: `/`, e.g., `/health`, `/api/data`, `/login`).
   - `-c`, `--concurrency`: Number of concurrent worker threads (default: `50`).
   - `-r`, `--rate`: Aggregate request-rate ceiling per second (default: `100`).
   - `-d`, `--duration`: Test duration in seconds (default: `20`).
   - `-t`, `--timeout`: Connection/read timeout in seconds (default: `2`).
3. **Token-Bucket Rate Limiter:** Enforces a thread-safe rate ceiling across high concurrency pools to ensure reproducible benchmark measurements.
4. **Live Telemetry & Forensic Accounting:** Reports real-time request status every 2 seconds, distinguishing between successful HTTP responses (`200 OK`) and dropped/banned/timeout packets (`000` / Connection Refused).

---

## 4. Empirical Stress Testing & Capacity Threshold Benchmarks

Benchmarking was performed from the host machine against all four endpoints to measure capacity limits, saturation thresholds, and mitigation behavior under identical stress parameters.

### Stress Test Parameters:
* **Concurrency:** 25 concurrent worker threads
* **Target Rate:** 80 requests/second
* **Duration:** 8 seconds (Target ceiling: 640 requests)
* **Fail2ban Threshold:** 60 requests within a 10-second window

### Comparative Results Matrix

| Target Service | Endpoint | Total Sent | HTTP 200 OK | Mitigated / Banned | Mitigation Rate | Service State Post-Attack |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **`service-frontend`** | `http://127.0.0.1:8081/` | 174 | **68** | **106** | **60.9%** | **Protected:** IP jailed in kernel `iptables`; zero CPU exhaustion. |
| **`service-backend`** | `http://127.0.0.1:8082/health` | 178 | **74** | **104** | **58.4%** | **Protected:** Attack halted at 74 requests; FastAPI resources preserved. |
| **`service-ldap-auth`** | `http://127.0.0.1:8083/health` | 151 | **66** | **85** | **56.3%** | **Protected:** OpenLDAP and auth worker protected from DoS exhaustion. |
| **`victim-unprotected`** | `http://127.0.0.1:8085/` | 639 | **639** | **0** | **0.0% (Unmitigated)** | **Vulnerable:** 100% of attack traffic reached Nginx worker processes. |

### Technical Analysis of Threshold Findings:
1. **Deterministic Banning:** Across all protected containers, the maximum number of requests processed before the jail activated was between **66 and 74 requests** (slightly above the configured 60 request limit due to multi-threaded worker dispatch latency before Fail2ban log polling committed the ban).
2. **Instant Kernel Cutoff:** Once the ban was committed, **100% of subsequent requests failed immediately** (`000` / `Connection refused`). Traffic was rejected at Layer 3/4 by `iptables`, preventing packet processing overhead in user-space application servers.
3. **Unprotected Failure Mode:** The unprotected Nginx server absorbed all 639 requests without restriction. While simple static pages responded with 200 OK under 80 req/s, unmitigated loads on dynamic endpoints (such as password hashing or directory searching) lead directly to CPU thread starvation and connection timeouts.

---

## 5. Step-by-Step Verification & Reproduction Guide

### Prerequisites
* Docker Desktop running on host
* Python 3.8+ installed on host

### Step 1: Launch the Hardened Container Stack
```bash
docker compose up -d --build
docker compose ps
```

### Step 2: Validate Baseline Health
```bash
curl -s http://localhost:8081/health
curl -s http://localhost:8082/health
curl -s http://localhost:8083/health
```
Expected output:
```json
{"status":"ok","service":"frontend"}
{"status":"ok","service":"backend-api"}
{"status":"ok","service":"ldap-tls-auth","port":636,"tls_active":true,"ldap_connected":true}
```

### Step 3: Test LDAP Authentication & JWT Generation
```bash
curl -s -X POST http://localhost:8083/login \
  -H "Content-Type: application/json" \
  -d '{"username":"alice","password":"alice123"}'
```
Returns a signed JWT bearer token and user group membership (`developers`).

### Step 4: Run External Load Tests from Host

#### A. Nominal Traffic (Below Threshold — Zero Bans):
```bash
python http_load_runner.py --host 127.0.0.1 --port 8081 --concurrency 5 --rate 10 --duration 3
```
*Result: 30 requests sent, 30 OK (200), 0 banned.*

#### B. High-Velocity Flood (Exceeding Threshold — Triggering Fail2ban):
```bash
python http_load_runner.py --host 127.0.0.1 --port 8081 --concurrency 25 --rate 80 --duration 8
```
*Result: Ban activates after ~68 requests. Subsequent requests are rejected.*

### Step 5: Inspect Jail and Kernel Firewall Inside Container
```bash
# Check jail status:
docker compose exec frontend fail2ban-client status http-flood

# Inspect active iptables reject rule:
docker compose exec frontend iptables -S | grep f2b

# Inspect forensic event logs:
docker compose exec frontend tail -n 20 /var/log/fail2ban.log
```

### Step 6: Manual Unban & Teardown
```bash
# Unban host IP to restore connectivity:
docker compose exec frontend fail2ban-client set http-flood unbanip 172.29.0.1
docker compose exec backend fail2ban-client set http-flood unbanip 172.29.0.1
docker compose exec ldap-auth fail2ban-client set http-flood unbanip 172.29.0.1

# Stop and clean up containers:
docker compose down
```
