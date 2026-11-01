FROM python:3.12-alpine
RUN apk add --no-cache curl
COPY flood.py /flood.py
RUN chmod +x /flood.py
CMD ["sleep", "infinity"]
