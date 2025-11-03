#!/bin/bash
set -euo pipefail

BASE="/opt/ngsoc-deploy"
log() { echo -e "[create_dirs] $*"; }

# === Estrutura principal (não altera nomes, apenas garante existência) ===
DIRS_MAIN=(
  "$BASE/data/harbor"
  "$BASE/data/metasploit"
  "$BASE/data/mitmproxy"
  "$BASE/data/openvas"
  "$BASE/data/trivy"
  "$BASE/data/trivy-proxy"
  "$BASE/data/zap"
  "$BASE/docs"
  "$BASE/exports"
  "$BASE/logs"
  "$BASE/reports"
)

for d in "${DIRS_MAIN[@]}"; do
  sudo mkdir -p "$d"
done

# === Donos e permissões específicas (conforme auditoria real) ===

# --- DATA ---
sudo chown -R root:root        "$BASE/data"
sudo chmod 755                 "$BASE/data"

sudo chown -R root:root        "$BASE/data/metasploit"
sudo chmod 700                 "$BASE/data/metasploit"

sudo chown -R wagner:wagner    "$BASE/data/mitmproxy"
sudo chmod 775                 "$BASE/data/mitmproxy"

sudo chown -R 1001:1001        "$BASE/data/openvas"
sudo chmod 775                 "$BASE/data/openvas"

sudo chown -R root:root        "$BASE/data/trivy"
sudo chmod 755                 "$BASE/data/trivy"

sudo chown -R root:997         "$BASE/data/trivy-proxy"
sudo chmod 755                 "$BASE/data/trivy-proxy"

sudo chown -R root:root        "$BASE/data/zap"
sudo chmod 755                 "$BASE/data/zap"

# --- DOCS ---
sudo chown -R root:997         "$BASE/docs"
sudo chmod 755                 "$BASE/docs"

# --- EXPORTS ---
sudo chown -R root:root        "$BASE/exports"
sudo chmod 755                 "$BASE/exports"

# --- LOGS ---
sudo chown -R root:root        "$BASE/logs"
sudo chmod 755                 "$BASE/logs"

sudo chown -R 10000:10000      "$BASE/logs/harbor"
sudo chmod 755                 "$BASE/logs/harbor"

sudo chown -R root:syslog      "$BASE/logs/metasploit"
sudo chmod 750                 "$BASE/logs/metasploit"

sudo chown -R root:997         "$BASE/logs/mitmproxy"
sudo chmod 777                 "$BASE/logs/mitmproxy"

sudo chown -R syslog:adm       "$BASE/logs/openvas"
sudo chmod 750                 "$BASE/logs/openvas"

sudo chown -R syslog:adm       "$BASE/logs/trivy"
sudo chmod 750                 "$BASE/logs/trivy"

sudo chown -R root:root        "$BASE/logs/zap"
sudo chmod 755                 "$BASE/logs/zap"

# --- REPORTS ---
sudo chown -R root:root        "$BASE/reports"
sudo chmod 755                 "$BASE/reports"

# --- Playbooks e Scripts (mantém padrão do menu) ---
sudo chown -R root:root        "$BASE/ansible" "$BASE/scripts"
sudo chmod -R 750              "$BASE/ansible" "$BASE/scripts"
sudo find "$BASE/scripts" -type f -name "*.sh" -exec sudo chmod 750 {} \;

log "Permissões e donos ajustados conforme ambiente atual."
exit 0
