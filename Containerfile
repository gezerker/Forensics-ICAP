# Forensics ICAP server
#   podman build -t forensics-icap .
#   podman run -d --name forensics-icap -p 1344:1344 \
#       -v ./captures:/data:Z --userns=keep-id:uid=1001,gid=1001 forensics-icap
FROM docker.io/library/python:3.13-slim

LABEL org.opencontainers.image.title="forensics-icap" \
      org.opencontainers.image.description="Passive ICAP server that saves REQMOD/RESPMOD content to disk for review" \
      org.opencontainers.image.source="https://github.com/gezerker/Forensics-ICAP"

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    ICAP_PORT=1344 \
    CAPTURE_DIR=/data/captures

RUN groupadd --gid 1001 icap \
 && useradd --uid 1001 --gid 1001 --no-create-home --shell /usr/sbin/nologin icap \
 && mkdir -p /data/captures /certs \
 && chown -R 1001:1001 /data

COPY --chmod=0755 icap_server.py /app/icap_server.py

USER 1001:1001
WORKDIR /data
VOLUME ["/data"]
EXPOSE 1344 11344

# Only honoured with "podman build --format docker"; the Quadlet unit sets its own.
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD ["python3", "/app/icap_server.py", "--healthcheck"]

STOPSIGNAL SIGTERM
ENTRYPOINT ["python3", "/app/icap_server.py"]
