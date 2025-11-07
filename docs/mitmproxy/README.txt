NGSOC MITMPROXY - README
========================

Image (local)  : myrepo/ngsoc-mitmproxy:custom-12.1.2
Image (prod)   : ngsoc-mitmproxy:prod
Registry target: (none)

Runtime notes:
- Default web UI: port 8090 (mitmweb)
- Proxy port: 8089
- Default web password: 'zap' (change in production)
- Recommended host directories to mount:
  /opt/ngsoc-deploy/logs/mitmproxy  -> container: /opt/ngsoc-deploy/logs/mitmproxy
  /opt/ngsoc-deploy/exports/mitmproxy -> container: /opt/ngsoc-deploy/exports/mitmproxy
  /opt/ngsoc-deploy/data/mitmproxy -> container: /opt/ngsoc-deploy/data/mitmproxy

Example docker run (recommended for rsyslog host ingestion & restart on boot):
docker run -d --name ngsoc_mitmproxy \
  --restart unless-stopped \
  -p 8089:8089 -p 8090:8090 \
  -v /opt/ngsoc-deploy/logs/mitmproxy:/opt/ngsoc-deploy/logs/mitmproxy:rw \
  -v /opt/ngsoc-deploy/exports/mitmproxy:/opt/ngsoc-deploy/exports/mitmproxy:ro \
  -v /opt/ngsoc-deploy/data/mitmproxy:/opt/ngsoc-deploy/data/mitmproxy:rw \
  myrepo/ngsoc-mitmproxy:custom-12.1.2

Suggested docker-compose snippet:
services:
  mitmproxy:
    image: myrepo/ngsoc-mitmproxy:custom-12.1.2
    container_name: ngsoc_mitmproxy
    restart: unless-stopped
    ports:
      - "8089:8089"
      - "8090:8090"
    volumes:
      - /opt/ngsoc-deploy/logs/mitmproxy:/opt/ngsoc-deploy/logs/mitmproxy:rw
      - /opt/ngsoc-deploy/exports/mitmproxy:/opt/ngsoc-deploy/exports/mitmproxy:ro
      - /opt/ngsoc-deploy/data/mitmproxy:/opt/ngsoc-deploy/data/mitmproxy:rw

RSYSLOG:
- Configure rsyslog on the host to tail /opt/ngsoc-deploy/logs/mitmproxy/*.log and forward to your central syslog (e.g. 1514/tcp).
- Example: create /etc/rsyslog.d/30-mitm.conf with a FileMonitor or imfile rules.

