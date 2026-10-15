# Forensics-ICAP

A passive ICAP server that runs in a Podman container. You can connect it to an SSE platform, secure web gateway, or proxy (Squid, Netskope, Zscaler, Skyhigh, …). It **never changes traffic**. Every REQMOD/RESPMOD it gets is written to disk so analysts can review it later.

- Supports RFC 3507 OPTIONS, REQMOD, and RESPMOD, with previews (`100 Continue`), `ieof`, keep-alive, and `204 No Content`.
- Works over plain ICAP (port 1344) or ICAPS/TLS (port 11344 by convention).
- Uses only the Python standard library. The image is `python:3.13-slim` plus one file.
- Fails open: if a capture can't be written, the error is logged and the client still gets its answer.

## Quick start (Podman)

```bash
podman build -t forensics-icap .

mkdir -p captures
podman run -d --name forensics-icap \
  -p 1344:1344 \
  -v ./captures:/data:Z \
  --userns=keep-id:uid=1001,gid=1001 \
  forensics-icap

podman logs -f forensics-icap
```

`--userns=keep-id:uid=1001,gid=1001` (Podman 4.3+) makes the container's `icap` user map to *your* host user. Captured files in `./captures` then belong to you. `:Z` relabels the directory for SELinux. If you'd rather not bind-mount, use a named volume: `-v forensics-icap-data:/data`.

Point your gateway at:

| Mode    | URL                                |
|---------|------------------------------------|
| REQMOD  | `icap://<host>:1344/reqmod`        |
| RESPMOD | `icap://<host>:1344/respmod`       |

Every service path is accepted. `/reqmod` and `/respmod` only change what OPTIONS advertises.

### As a systemd service (Quadlet)

```bash
cp deploy/forensics-icap.container ~/.config/containers/systemd/
systemctl --user daemon-reload
systemctl --user start forensics-icap
```

### ICAPS / TLS

```bash
podman run -d --name forensics-icap -p 11344:11344 \
  -v ./captures:/data:Z -v ./certs:/certs:ro,Z \
  -e ICAP_PORT=11344 -e TLS_CERT=/certs/cert.pem -e TLS_KEY=/certs/key.pem \
  --userns=keep-id:uid=1001,gid=1001 forensics-icap
```

## What gets saved

```
captures/
├── index.jsonl                                  one line per transaction (grep/jq friendly)
└── 2026/10/15/
    └── 141502_reqmod_3f9c2a1b7d4e/
        ├── metadata.json                        time, client IP, user, URL, status, hashes, all headers
        ├── http_request_headers.txt             encapsulated HTTP request headers
        ├── http_response_headers.txt            encapsulated HTTP response headers (RESPMOD)
        ├── body.pdf                             raw body, extension from Content-Type / filename
        ├── body_decoded.html                    gzip/deflate removed (when Content-Encoding is set)
        └── parts/                               files pulled out of multipart/form-data uploads
            ├── 01_field_comment.txt
            └── 02_quarterly-report.xlsx
```

A capture is written to a hidden `.partial-*` directory first and renamed only when it's complete, so you never review half-written data. `metadata.json` records the body's SHA-256 and MD5 for chain of custody and hash lookups.

`X-Client-IP` and the user headers (`X-Authenticated-User`, `X-Client-Username`, `X-User`) are pulled into the metadata. All ICAP headers are kept as well.

### Reviewing

```bash
# Latest 20 transactions
tail -n 20 captures/index.jsonl | jq -c '{time, user, client_ip, url, content_type, bytes}'

# Everything a given user uploaded
jq -c 'select(.user=="alice" and .method=="REQMOD" and .bytes>0)' captures/index.jsonl

# Find a file by hash
grep <sha256> captures/index.jsonl
```

> ⚠️ Captured content can be malware or sensitive data. Review it on an isolated host. Restrict access to the capture directory, which the server creates with mode `0750`/`0640`. Plan a retention policy, for example `find captures -mindepth 3 -maxdepth 3 -type d -mtime +90 -exec rm -rf {} +`.

## Configuration

| Variable               | Default          | Description |
|------------------------|------------------|-------------|
| `ICAP_PORT`            | `1344`           | Listen port |
| `ICAP_HOST`            | `0.0.0.0`        | Listen address |
| `CAPTURE_DIR`          | `/data/captures` | Where captures are written |
| `MAX_BODY_BYTES`       | `104857600`      | Bodies larger than this are truncated **on disk**. The full size and hash are still recorded, and traffic is unaffected. |
| `SAVE_EMPTY`           | `true`           | Also record transactions with no body, such as plain GETs. Set to `false` to keep only content. |
| `ICAP_PREVIEW`         | `0`              | Preview size advertised in OPTIONS |
| `ICAP_OPTIONS_TTL`     | `3600`           | OPTIONS cache lifetime advertised to clients |
| `ICAP_MAX_CONNECTIONS` | `100`            | Advertised in OPTIONS |
| `ICAP_SOCKET_TIMEOUT`  | `300`            | Idle socket timeout (seconds) |
| `TLS_CERT`, `TLS_KEY`  | unset            | Turn on ICAPS when both are set |
| `LOG_LEVEL`            | `INFO`           | `DEBUG` logs each request |

## Development

```bash
python3 -m unittest discover -s tests -v     # end-to-end tests over real sockets
CAPTURE_DIR=./captures python3 icap_server.py  # run without a container
```

Test with `c-icap-client` (package `c-icap`):

```bash
echo 'hello' > /tmp/f.txt
c-icap-client -i 127.0.0.1 -p 1344 -s reqmod -f /tmp/f.txt -req http://example.com/upload -v
```
