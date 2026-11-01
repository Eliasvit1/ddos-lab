#!/bin/bash
set -e
cd "$(dirname "$0")"

echo ">>> Building and starting containers..."
docker compose up -d --build

echo; echo ">>> Waiting for both Nginx sites to become ready"
ready=false
for attempt in {1..30}; do
  if docker compose exec -T attacker sh -c \
    'curl -fsS http://victim-protected/ >/dev/null && curl -fsS http://victim-unprotected/ >/dev/null'; then
    ready=true
    break
  fi
  sleep 1
done
if [[ "$ready" != true ]]; then
  echo "ERROR: one or both Nginx sites did not become ready. Container status/logs:"
  docker compose ps
  docker compose logs --tail=50 victim-protected victim-unprotected attacker
  exit 1
fi

echo; echo ">>> Verifying Fail2ban is running"
if ! docker compose exec -T victim-protected fail2ban-client status http-flood; then
  docker compose logs --tail=80 victim-protected
  exit 1
fi
# Clear a ban left over from a previous run so the initial check is meaningful.
docker compose exec -T victim-protected \
  fail2ban-client set http-flood unbanip 172.29.0.20 >/dev/null 2>&1 || true

echo; echo ">>> Sanity check: both sites respond"
docker compose exec -T attacker curl -s -o /dev/null -w "protected:   %{http_code}\n"   http://victim-protected/
docker compose exec -T attacker curl -s -o /dev/null -w "unprotected: %{http_code}\n" http://victim-unprotected/

echo; echo ">>> fail2ban status BEFORE flood"
docker compose exec -T victim-protected fail2ban-client status http-flood

echo; echo ">>> Launching bounded Python test from the attacker container (about DURATION*2 seconds)"
docker compose exec -T attacker python /flood.py

echo; echo ">>> fail2ban status AFTER flood"
docker compose exec -T victim-protected fail2ban-client status http-flood

echo; echo ">>> iptables rules created by fail2ban on the protected container"
docker compose exec -T victim-protected iptables -S | grep -i f2b || true

echo; echo ">>> fail2ban log (last lines)"
docker compose exec -T victim-protected tail -n 15 /var/log/fail2ban.log

cat <<MSG

Useful next steps:
  docker compose exec victim-protected fail2ban-client set http-flood unbanip 172.29.0.20 # manual unban
  docker compose exec attacker python /flood.py                                           # run the bounded test again
  docker compose down                                                                     # cleanup
MSG
