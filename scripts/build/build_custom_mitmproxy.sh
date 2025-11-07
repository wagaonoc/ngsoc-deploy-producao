#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# build_custom_mitmproxy.sh - NGSOC
# Build a reproducible custom mitmproxy image (clean + audited)
# Produces image, optional trivy scan, offline tar.gz and README
# ============================================================

# ---------- Config (edite conforme necessário) ----------
# Base image immutable digest (recommended). If empty, fallback to tag "mitmproxy/mitmproxy:latest"
BASE_DIGEST="${BASE_DIGEST:-mitmproxy/mitmproxy@sha256:4ff0437c5cd20babca7b1a563391fc609e66ef93bca60c98d191bdd439809afb}"

# Paths in the host NGSOC structure (source)
NGSOC_BASE="/opt/ngsoc-deploy"
SRC_DATA="${NGSOC_BASE}/data/mitmproxy"
SRC_LOGS="${NGSOC_BASE}/logs/mitmproxy"
SRC_EXPORTS="${NGSOC_BASE}/exports/mitmproxy"
SRC_DOCS="${NGSOC_BASE}/docs/mitmproxy"

# Export/build workspace (in user home)
EXPORT_BASE="${HOME}/ngsoc_export"
EXPORT_DIR="${EXPORT_BASE}/mitmproxy"

# Image tags
LOCAL_TAG="${LOCAL_TAG:-myrepo/ngsoc-mitmproxy:custom-12.1.2}"
PROD_TAG="${PROD_TAG:-ngsoc-mitmproxy:prod}"         # tag suggested for production
REGISTRY_TARGET="${REGISTRY_TARGET:-}"               # e.g. myharbor.local/ngsoc/mitmproxy:custom-12.1.2

# Minimum free space (MB)
MIN_FREE_MB=${MIN_FREE_MB:-800}

# Temporary log
BUILD_LOG="/tmp/build_custom_mitmproxy.log"
# --------------------------------------------------------

echo
echo "=== NGSOC MITMPROXY CUSTOM IMAGE BUILD ==="
echo "Export dir: $EXPORT_DIR"
echo "Local image tag: $LOCAL_TAG"
[ -n "$REGISTRY_TARGET" ] && echo "Registry target: $REGISTRY_TARGET" || echo "Registry target: (none) — push step will be skipped"
echo

# prereq check
if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: docker not found. Install docker." >&2
  exit 1
fi

# ensure build workspace
mkdir -p "$EXPORT_DIR"
rm -rf "${EXPORT_DIR:?}/"*
mkdir -p "$EXPORT_DIR"/{data,logs,exports,docs}

# check free space on filesystem hosting EXPORT_BASE
avail_kb=$(df --output=avail -k "$EXPORT_BASE" 2>/dev/null | tail -1 || echo 0)
avail_mb=$((avail_kb/1024))
if [ "$avail_mb" -lt "$MIN_FREE_MB" ]; then
  echo "WARNING: free space on $(dirname "$EXPORT_BASE") is ${avail_mb}MB < ${MIN_FREE_MB}MB."
  read -r -p "Continue anyway? (y/N) " yn
  if [[ "$yn" != "y" && "$yn" != "Y" ]]; then
    echo "Aborting due to insufficient disk space."
    exit 2
  fi
fi

# helper copy
copy_if_exists() {
  local src=$1 dst=$2
  if [ -d "$src" ]; then
    echo "Copying $src -> $dst"
    /bin/cp -aL "${src}/." "$dst/" || /bin/cp -a "${src}/." "$dst/" || true
  else
    echo "Notice: source not found: $src (skipping)"
  fi
}

copy_if_exists "$SRC_DATA" "$EXPORT_DIR/data"
copy_if_exists "$SRC_LOGS" "$EXPORT_DIR/logs"
copy_if_exists "$SRC_EXPORTS" "$EXPORT_DIR/exports"
copy_if_exists "$SRC_DOCS" "$EXPORT_DIR/docs"

echo
echo "Workspace summary:"
du -sh "$EXPORT_DIR" || true
find "$EXPORT_DIR" -maxdepth 2 -type f -printf "%p %kKB\n" | sed -n '1,200p' || true
echo

# quick secret scan
echo "Quick grep for common secret keywords in exported files (no replacement done by script):"
grep -R --line-number -iE "password|passwd|secret|token|key|private" "$EXPORT_DIR" || true
echo "If sensitive secrets appear, remove or replace them before building the image."
echo

# sanitize private keys - only remove files that contain 'BEGIN RSA PRIVATE KEY'
echo "Sanitizing exported workspace (removing private key PEMs)..."
find "$EXPORT_DIR" -type f -name "*.pem" -exec sh -c 'grep -q "BEGIN .*PRIVATE KEY" "$1" && printf "REMOVING: %s\n" "$1" && rm -f "$1"' _ {} \; || true
echo "Remaining PEM files (if any):"
find "$EXPORT_DIR" -type f -name "*.pem" -printf "%p\n" || true
echo

# write Dockerfile
cat > "$EXPORT_DIR/Dockerfile" <<EOF
FROM ${BASE_DIGEST}

LABEL org.ngsoc.project="ngsoc" \\
      org.ngsoc.component="mitmproxy" \\
      org.ngsoc.version="custom-12.1.2" \\
      maintainer="Wagner <you@example.com>"

# create NGSOC layout and copy exported artifacts
COPY data/ /opt/ngsoc-deploy/data/mitmproxy/
COPY logs/ /opt/ngsoc-deploy/logs/mitmproxy/
COPY exports/ /opt/ngsoc-deploy/exports/mitmproxy/
COPY docs/ /opt/ngsoc-deploy/docs/mitmproxy/

# runtime dirs and permissions
RUN mkdir -p /opt/ngsoc-deploy/reports/mitmproxy \\
 && mkdir -p /home/mitmproxy/.mitmproxy \\
 && chown -R root:root /opt/ngsoc-deploy \\
 && chmod -R 0755 /opt/ngsoc-deploy || true

# expose default mitm ports
EXPOSE 8089 8090

# recommend a mount point for host logs/exports (user should bind host dir)
VOLUME ["/opt/ngsoc-deploy/logs/mitmproxy", "/opt/ngsoc-deploy/exports/mitmproxy"]

ENV MITMPROXY_WEB_PASSWORD=zap \\
    NGSOC_HOME=/opt/ngsoc-deploy \\
    MITMPROXY_DATA_DIR=/opt/ngsoc-deploy/data/mitmproxy \\
    MITMPROXY_EXPORT_DIR=/opt/ngsoc-deploy/exports/mitmproxy

ENTRYPOINT ["mitmweb"]
CMD ["--listen-host","0.0.0.0","--listen-port","8089","--web-host","0.0.0.0","--web-port","8090","--set","web_password=zap"]
EOF

echo "Dockerfile written to $EXPORT_DIR/Dockerfile"
echo

# build image (pull base to ensure latest digest available)
echo "Starting docker build..."
cd "$EXPORT_DIR"
if docker build --pull -t "$LOCAL_TAG" . 2>&1 | tee "$BUILD_LOG"; then
  echo "Docker build completed: $LOCAL_TAG"
else
  echo "ERROR: docker build failed. See $BUILD_LOG" >&2
  tail -n 80 "$BUILD_LOG" || true
  exit 11
fi

# optional quick check inside built image
echo "Inspecting built image file presence (quick check)..."
docker run --rm --entrypoint sh "$LOCAL_TAG" -c "ls -la /opt/ngsoc-deploy || true"
docker run --rm --entrypoint sh "$LOCAL_TAG" -c "ls -la /opt/ngsoc-deploy/logs/mitmproxy || true"

# optional trivy scan
if command -v trivy >/dev/null 2>&1; then
  echo
  echo "Running Trivy scan (HIGH+CRITICAL)..."
  trivy image --severity HIGH,CRITICAL "$LOCAL_TAG" || echo "Trivy returned non-zero (inspect output above)."
else
  echo "Trivy not installed; skipping image security scan."
fi

# save image to tar.gz
OUT_TAR="${EXPORT_DIR}/mitmproxy_custom_12.1.2.tar"
echo
echo "Saving image to tar: $OUT_TAR (this may take time depending on size)..."
docker save "$LOCAL_TAG" -o "$OUT_TAR"
gzip -f "$OUT_TAR"
echo "Saved and gzipped: ${OUT_TAR}.gz"
ls -lh "${OUT_TAR}.gz" || true

# create README on host (path guaranteed)
README_DIR="${NGSOC_BASE}/docs/mitmproxy"
mkdir -p "$README_DIR"
README_FILE="${README_DIR}/README.txt"

cat > "$README_FILE" <<EOM
NGSOC MITMPROXY - README
========================

Image (local)  : $LOCAL_TAG
Image (prod)   : $PROD_TAG
Registry target: ${REGISTRY_TARGET:-(none)}

Runtime notes:
- Default web UI: port 8090 (mitmweb)
- Proxy port: 8089
- Default web password: 'zap' (change in production)
- Recommended host directories to mount:
  /opt/ngsoc-deploy/logs/mitmproxy  -> container: /opt/ngsoc-deploy/logs/mitmproxy
  /opt/ngsoc-deploy/exports/mitmproxy -> container: /opt/ngsoc-deploy/exports/mitmproxy
  /opt/ngsoc-deploy/data/mitmproxy -> container: /opt/ngsoc-deploy/data/mitmproxy

Example docker run (recommended for rsyslog host ingestion & restart on boot):
docker run -d --name ngsoc_mitmproxy \\
  --restart unless-stopped \\
  -p 8089:8089 -p 8090:8090 \\
  -v /opt/ngsoc-deploy/logs/mitmproxy:/opt/ngsoc-deploy/logs/mitmproxy:rw \\
  -v /opt/ngsoc-deploy/exports/mitmproxy:/opt/ngsoc-deploy/exports/mitmproxy:ro \\
  -v /opt/ngsoc-deploy/data/mitmproxy:/opt/ngsoc-deploy/data/mitmproxy:rw \\
  $LOCAL_TAG

Suggested docker-compose snippet:
services:
  mitmproxy:
    image: $LOCAL_TAG
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

EOM

echo "README written to: $README_FILE"
echo

# optional push to registry
if [ -n "$REGISTRY_TARGET" ]; then
  echo "Tagging for registry: $REGISTRY_TARGET"
  docker tag "$LOCAL_TAG" "$REGISTRY_TARGET"
  read -r -p "Push to $REGISTRY_TARGET now? (y/N) " yn
  if [[ "$yn" =~ ^[Yy]$ ]]; then
    docker push "$REGISTRY_TARGET"
  else
    echo "Skipping push."
  fi
fi

echo
echo "=== BUILD COMPLETE ==="
echo "Local image: $LOCAL_TAG"
echo "Offline bundle: ${OUT_TAR}.gz"
echo "README: $README_FILE"
exit 0
