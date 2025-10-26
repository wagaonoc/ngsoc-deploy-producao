#!/usr/bin/env bash
# discover_gvm_state.sh
# Non-destructive discovery script for GVM/OpenVAS environment under /opt/ngsoc-deploy
# Produces a report directory with JSON/text files describing containers, images, volumes, ports, file perms, logs, etc.
#
# Usage:
#   sudo /opt/ngsoc-deploy/scripts/discover_gvm_state.sh            # normal run (no GSA login test)
#   sudo /opt/ngsoc-deploy/scripts/discover_gvm_state.sh --test-gsa # run and attempt a GSA login test (use with care)
#
set -euo pipefail

REPORT_BASE="/opt/ngsoc-deploy/reports"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"
OUTDIR="${REPORT_BASE}/scan_${TIMESTAMP}"
mkdir -p "$OUTDIR"
echo "Report directory: $OUTDIR"

# Patterns to identify relevant containers
CANDIDATES_REGEX="gvm|gvmd|gsa|openvas|greenbone|scanner|redis|postgres|pg-gvm|zap|mitm|ngsoc"

# Flags
TEST_GSA=false
if [[ "${1:-}" == "--test-gsa" || "${2:-}" == "--test-gsa" ]]; then
  TEST_GSA=true
fi

# Helper to print header in files
h() { printf "\n==== %s ====\n\n" "$1" >> "$OUTFILE"; }

# 1) Basic system info
OUTFILE="$OUTDIR/system-info.txt"
echo "Collecting system info -> $OUTFILE"
{
  echo "Generated: $(date -u)"
  echo
  echo "Hostname: $(hostname -f 2>/dev/null || hostname)"
  echo "Uptime  : $(uptime -p 2>/dev/null || echo 'n/a')"
  uname -a
  echo
  echo "OS release:"
  if [ -f /etc/os-release ]; then
    sed -n '1,10p' /etc/os-release
  fi
  echo
  echo "Kernel modules (first 50):"
  lsmod | head -n 50
} > "$OUTFILE"

# 2) Docker basic lists
OUTFILE="$OUTDIR/docker-ps.txt"
echo "Collecting docker ps -> $OUTFILE"
if command -v docker >/dev/null 2>&1; then
  docker ps -a --format 'table {{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' > "$OUTFILE" 2>&1 || docker ps -a > "$OUTFILE" 2>&1
else
  echo "docker: NOT FOUND" > "$OUTFILE"
fi

OUTFILE="$OUTDIR/docker-images.txt"
docker images --format 'table {{.Repository}}\t{{.Tag}}\t{{.ID}}\t{{.Size}}' > "$OUTFILE" 2>&1 || true

OUTFILE="$OUTDIR/docker-volumes.txt"
docker volume ls > "$OUTFILE" 2>&1 || true

# 3) Candidate containers discovery and inspect
OUTFILE="$OUTDIR/candidates.txt"
echo "Discovering candidate containers -> $OUTFILE"
docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}' | grep -Ei "$CANDIDATES_REGEX" || true > "$OUTFILE"

# For each candidate, save docker inspect and logs and mounts
while IFS= read -r line; do
  [ -z "$line" ] && continue
  NAME="$(awk -F'|' '{print $1}' <<< "$line")"
  IMAGE="$(awk -F'|' '{print $2}' <<< "$line")"
  echo "Inspecting container: $NAME (image: $IMAGE)"
  # docker inspect
  docker inspect "$NAME" > "$OUTDIR/docker-inspect-${NAME}.json" 2>/dev/null || echo "{}" > "$OUTDIR/docker-inspect-${NAME}.json"
  # last logs
  docker logs --tail 500 "$NAME" > "$OUTDIR/docker-logs-${NAME}.log" 2>&1 || echo "no logs" > "$OUTDIR/docker-logs-${NAME}.log"
done < <(docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}' | grep -Ei "$CANDIDATES_REGEX" || true)

# 4) Search for docker-compose files under /opt/ngsoc-deploy
OUTFILE="$OUTDIR/docker-compose-files.txt"
echo "Searching for docker-compose files -> $OUTFILE"
find /opt/ngsoc-deploy -type f -iname "docker-compose*.yml" -o -iname "docker-compose*.yaml" -maxdepth 5 -print > "$OUTFILE" 2>/dev/null || true

# 5) List /opt/ngsoc-deploy tree and permissions
OUTFILE="$OUTDIR/files-and-permissions.txt"
echo "Listing /opt/ngsoc-deploy files and permissions -> $OUTFILE"
{
  echo "Top-level listing:"
  ls -la /opt/ngsoc-deploy || true
  echo
  echo "Ansible playbooks directory:"
  ls -la /opt/ngsoc-deploy/Ansible || true
  ls -la /opt/ngsoc-deploy/Ansible/playbooks || true
  echo
  echo "Scripts directory:"
  ls -la /opt/ngsoc-deploy/scripts || true
  echo
  echo "Data directories (sizes and perms):"
  du -sh /opt/ngsoc-deploy/data/* 2>/dev/null || true
  find /opt/ngsoc-deploy/data -maxdepth 3 -printf '%M %u %g %s %p\n' 2>/dev/null | sed -n '1,200p' || true
  echo
  echo "Logs directory (sizes and perms):"
  du -sh /opt/ngsoc-deploy/logs/* 2>/dev/null || true
  find /opt/ngsoc-deploy/logs -maxdepth 3 -printf '%M %u %g %s %p\n' 2>/dev/null | sed -n '1,200p' || true
} > "$OUTFILE"

# 6) Show key scripts content (first N lines) to capture commands used for deploy
OUTFILE="$OUTDIR/scripts-summary.txt"
echo "Dumping key scripts -> $OUTFILE"
{
  echo "# /opt/ngsoc-deploy/scripts listing"
  ls -la /opt/ngsoc-deploy/scripts || true
  echo
  for f in /opt/ngsoc-deploy/scripts/*.sh; do
    [ -f "$f" ] || continue
    echo "==== FILE: $f ===="
    sed -n '1,400p' "$f" || true
    echo
  done
} > "$OUTFILE"

# 7) Network / open ports / firewall / processes
OUTFILE="$OUTDIR/open-ports.txt"
echo "Collecting open ports -> $OUTFILE"
if command -v ss >/dev/null 2>&1; then
  ss -tuln > "$OUTFILE" 2>&1 || true
else
  netstat -tuln > "$OUTFILE" 2>&1 || true
fi

OUTFILE="$OUTDIR/firewall.txt"
echo "Collecting firewall rules -> $OUTFILE"
if command -v ufw >/dev/null 2>&1; then
  ufw status verbose > "$OUTFILE" 2>&1 || iptables -L -n > "$OUTFILE" 2>&1 || true
else
  iptables -L -n > "$OUTFILE" 2>&1 || true
fi

OUTFILE="$OUTDIR/process-list.txt"
echo "Collecting process list -> $OUTFILE"
ps aux --sort=-%mem | sed -n '1,200p' > "$OUTFILE" 2>&1 || true

# 8) Docker-compose project list (compose v2+)
OUTFILE="$OUTDIR/docker-compose-projects.txt"
echo "Finding compose projects -> $OUTFILE"
docker compose ls --format '{{.Name}} {{.Status}} {{.Projects}}' > "$OUTFILE" 2>&1 || docker-compose ls > "$OUTFILE" 2>&1 || true

# 9) Packages and systemctl services
OUTFILE="$OUTDIR/packages.txt"
echo "Collecting installed packages (dpkg -l) -> $OUTFILE"
if command -v dpkg >/dev/null 2>&1; then
  dpkg -l | sed -n '1,200p' > "$OUTFILE" 2>&1 || true
else
  rpm -qa | sed -n '1,200p' > "$OUTFILE" 2>&1 || true
fi

OUTFILE="$OUTDIR/systemd-services.txt"
echo "Collecting systemd services (relevant) -> $OUTFILE"
systemctl list-units --type=service --state=running | grep -Ei "docker|gvm|openvas|greenbone|postgres|redis" -n || true > "$OUTFILE" 2>&1

# 10) Collect docker network info
OUTFILE="$OUTDIR/docker-networks.txt"
echo "Collecting docker network info -> $OUTFILE"
docker network ls > "$OUTFILE" 2>&1 || true
for net in $(docker network ls --format '{{.Name}}' 2>/dev/null || true); do
  docker network inspect "$net" > "$OUTDIR/docker-network-${net}.json" 2>/dev/null || true
done

# 11) Grab docker-compose override files and env files under project
OUTFILE="$OUTDIR/env-files-found.txt"
echo "Searching for .env files under /opt/ngsoc-deploy -> $OUTFILE"
find /opt/ngsoc-deploy -type f -iname ".env" -maxdepth 5 -print > "$OUTFILE" 2>/dev/null || true

# 12) Collect permissions for critical playbooks (playbook files)
OUTFILE="$OUTDIR/playbooks-permissions.txt"
echo "Collecting playbooks permissions -> $OUTFILE"
find /opt/ngsoc-deploy/Ansible/playbooks -maxdepth 1 -type f -printf '%M %u %g %s %p\n' > "$OUTFILE" 2>/dev/null || true

# 13) If GSA is reachable on port 9392, capture a simple HTTP header response
OUTFILE="$OUTDIR/gsa_headers.txt"
echo "Trying to capture GSA headers (if listening on 127.0.0.1:9392) -> $OUTFILE"
curl -Is http://127.0.0.1:9392/ 2>/dev/null | sed -n '1,200p' > "$OUTFILE" || echo "GSA not reachable on 127.0.0.1:9392" > "$OUTFILE"

# 14) Optionally test GSA login (OFF by default)
if [ "$TEST_GSA" = true ]; then
  read -r -p "Enter GSA URL (full, e.g. http://192.168.100.23:9392/login): " GSA_URL
  read -r -p "Enter username: " GSA_USER
  read -r -s -p "Enter password: " GSA_PASS
  echo
  OUTFILE="$OUTDIR/gsa_login_test.txt"
  echo "Testing login to $GSA_URL (response saved to $OUTFILE)"
  # naive POST (may depend on GSA login form fields — adjust if necessary)
  curl -s -L -c "$OUTDIR/cookies.txt" -d "username=$GSA_USER&password=$GSA_PASS" "$GSA_URL" -o "$OUTDIR/gsa_login_response.html" || true
  echo "Saved response in gsa_login_response.html and cookies.txt" > "$OUTFILE"
else
  echo "GSA login test skipped (default). Use --test-gsa to enable interactive login test." > "$OUTDIR/gsa_login_test.txt"
fi

# 15) Summarize key findings
OUTFILE="$OUTDIR/summary.txt"
echo "Preparing summary -> $OUTFILE"
{
  echo "Report generated: $TIMESTAMP"
  echo
  echo "Containers matching pattern ($CANDIDATES_REGEX):"
  docker ps -a --format '{{.Names}}|{{.Image}}|{{.Status}}|{{.Ports}}' | grep -Ei "$CANDIDATES_REGEX" || echo "None found"
  echo
  echo "GSA endpoint quick header (127.0.0.1:9392):"
  sed -n '1,40p' "$OUTDIR/gsa_headers.txt" || true
  echo
  echo "Docker images (top 30):"
  docker images --format '{{.Repository}}:{{.Tag}} {{.ID}} {{.Size}}' | sed -n '1,30p' || true
  echo
  echo "Important paths and permissions (top):"
  ls -ld /opt/ngsoc-deploy /opt/ngsoc-deploy/data /opt/ngsoc-deploy/logs /opt/ngsoc-deploy/Ansible || true
  echo
  echo "Note: Sensitive files (env, passwords) may have been listed. Review before sharing."
} > "$OUTFILE"

echo "Discovery complete. Reports available at: $OUTDIR"
echo "Suggested next step: compress the directory before sharing: sudo tar -czf /tmp/scan_${TIMESTAMP}.tgz -C /opt/ngsoc-deploy/reports scan_${TIMESTAMP}"
