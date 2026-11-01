FROM alpine:3.20

# Install system dependencies: Python, Nginx, Fail2ban, iptables
RUN apk add --no-cache python3 py3-pip nginx fail2ban bash iptables iproute2

WORKDIR /workspace

COPY requirements.txt .
RUN python3 -m venv /opt/venv && \
    /opt/venv/bin/pip install --no-cache-dir -r requirements.txt

ENV PATH="/opt/venv/bin:$PATH"

COPY app/ ./app/
COPY nginx.conf /etc/nginx/nginx.conf
COPY jail.local /etc/fail2ban/jail.local
COPY filter-http-flood.conf /etc/fail2ban/filter.d/http-flood.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
