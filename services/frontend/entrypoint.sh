#!/bin/bash
set -e
mkdir -p /var/log/nginx /var/run/fail2ban
rm -f /var/log/nginx/access.log /var/log/nginx/error.log
touch /var/log/nginx/access.log /var/log/nginx/error.log /var/log/fail2ban.log
rm -f /var/run/fail2ban/fail2ban.sock /var/run/fail2ban/fail2ban.pid

nginx -g 'daemon off;' &
sleep 1
fail2ban-client -x start

echo "[frontend-protected] Nginx + Fail2ban active. Monitoring access logs..."
exec tail -F /var/log/fail2ban.log
