FROM nginx:1.27-alpine
RUN apk add --no-cache fail2ban bash iptables iproute2

COPY nginx.conf /etc/nginx/nginx.conf
COPY site/ /usr/share/nginx/html/
COPY jail.local /etc/fail2ban/jail.local
COPY filter-http-flood.conf /etc/fail2ban/filter.d/http-flood.conf
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 80
ENTRYPOINT ["/entrypoint.sh"]
