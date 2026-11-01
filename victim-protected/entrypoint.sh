#!/bin/bash
set -e
mkdir -p /var/log/nginx /var/run/fail2ban
# The official nginx image links these paths to stdout/stderr. Fail2ban needs a
# real, readable access-log file, so replace the image's symlinks before nginx starts.
rm -f /var/log/nginx/access.log /var/log/nginx/error.log
touch /var/log/nginx/access.log /var/log/nginx/error.log /var/log/fail2ban.log
rm -f /var/run/fail2ban/fail2ban.sock /var/run/fail2ban/fail2ban.pid

nginx -g 'daemon off;' &
sleep 1
fail2ban-client -x start

echo "[victim-protected] nginx + fail2ban running. Following fail2ban log..."
exec tail -F /var/log/fail2ban.log
