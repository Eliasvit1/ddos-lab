#!/bin/bash
set -e
mkdir -p /var/log/nginx /var/run/fail2ban
rm -f /var/log/nginx/access.log /var/log/nginx/error.log
touch /var/log/nginx/access.log /var/log/nginx/error.log /var/log/fail2ban.log
rm -f /var/run/fail2ban/fail2ban.sock /var/run/fail2ban/fail2ban.pid

# Launch FastAPI backend via Uvicorn in background
uvicorn app.main:app --host 127.0.0.1 --port 8000 &
sleep 2

# Launch Nginx reverse proxy in background
nginx -g 'daemon off;' &
sleep 1

# Launch Fail2ban daemon
fail2ban-client -x start

echo "[backend-protected] FastAPI + Nginx + Fail2ban active. Monitoring access logs..."
exec tail -F /var/log/fail2ban.log
