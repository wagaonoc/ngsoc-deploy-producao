#!/bin/bash
set -euo pipefail
# ==========================================================
# create_rsyslog_structure.sh
# Cria diretórios e arquivos de configuração para o Rsyslog
# Idempotente (cria apenas o que faltar)
# Preserva e aplica permissões conforme auditoria real
# ==========================================================

BASE_CONF_DIR="/etc/rsyslog.d"
BASE_LOG_DIR="/var/log"
COMPONENTS=(harbor mitmproxy trivy openvas metasploit zap)

# === Mapeamento de donos/permissões por componente ===
declare -A COMP_DIR_OWNER=(
  [harbor]="root"
  [mitmproxy]="syslog"
  [trivy]="syslog"
  [openvas]="syslog"
  [metasploit]="syslog"
  [zap]="syslog"
)
declare -A COMP_DIR_GROUP=(
  [harbor]="syslog"
  [mitmproxy]="adm"
  [trivy]="adm"
  [openvas]="adm"
  [metasploit]="syslog"
  [zap]="adm"
)
declare -A COMP_DIR_MODE=(
  [harbor]="770"
  [mitmproxy]="750"
  [trivy]="750"
  [openvas]="750"
  [metasploit]="2750"
  [zap]="750"
)

LOG_FILE_MODE="0640"
CONF_DIR_MODE="755"
CONF_FILE_MODE="0644"

# === Funções auxiliares ===
log() { echo -e "[create_rsyslog] $*"; }
success() { echo -e "\e[1;32m[SUCCESS]\e[0m $*"; }
error() { echo -e "\e[1;31m[ERROR]\e[0m $*"; }

# === 0) Checagem inicial ===
if ! dpkg -l | grep -qE "^ii\s+rsyslog\b"; then
  error "Rsyslog não encontrado. Instale com: sudo apt install -y rsyslog"
  exit 1
fi

if ! systemctl is-active --quiet rsyslog; then
  log "Aviso: rsyslog não está ativo. Habilite com: sudo systemctl enable --now rsyslog"
else
  log "✅ Rsyslog instalado e ativo."
fi

# === 1) Estrutura /etc/rsyslog.d/<component>/ ===
for comp in "${COMPONENTS[@]}"; do
  conf_dir="${BASE_CONF_DIR}/${comp}"
  conf_file="${conf_dir}/${comp}_rsyslog.conf"

  mkdir -p "$conf_dir"
  chown root:root "$conf_dir"
  chmod "$CONF_DIR_MODE" "$conf_dir"

  if [ ! -f "$conf_file" ]; then
    log "Criando stub: $conf_file"
    cat > "$conf_file" <<EOF
# ${comp}_rsyslog.conf - gerado automaticamente
module(load="imfile" PollingInterval="10")

# input(type="imfile"
#       File="/opt/ngsoc-deploy/logs/${comp}/${comp}.log"
#       Tag="${comp}"
#       Severity="info"
#       Facility="local6"
#       reopenOnTruncate="on")

# if (\$programname == "${comp}" or \$syslogtag contains "${comp}") then {
#     action(type="omfile"
#            file="/var/log/${comp}/${comp}.log"
#            fileOwner="${COMP_DIR_OWNER[${comp}]}"
#            fileGroup="${COMP_DIR_GROUP[${comp}]}"
#            fileCreateMode="${LOG_FILE_MODE}"
#            reopenOnTruncate="on")
#     stop
# }
EOF
  fi

  chown root:root "$conf_file"
  chmod "$CONF_FILE_MODE" "$conf_file"
done

# === 2) Estrutura /var/log/<component>/ ===
for comp in "${COMPONENTS[@]}"; do
  log_dir="${BASE_LOG_DIR}/${comp}"
  log_file="${log_dir}/${comp}.log"

  owner="${COMP_DIR_OWNER[$comp]}"
  group="${COMP_DIR_GROUP[$comp]}"
  mode="${COMP_DIR_MODE[$comp]}"

  mkdir -p "$log_dir"
  chown -R "$owner:$group" "$log_dir"
  chmod "$mode" "$log_dir"

  if [ ! -f "$log_file" ]; then
    touch "$log_file"
    log "Arquivo criado: $log_file"
  fi

  chown "$owner:$group" "$log_file"
  chmod "$LOG_FILE_MODE" "$log_file"
done

# === 3) Resultado final ===
if [ $? -eq 0 ]; then
  success "Estrutura de diretórios e arquivos Rsyslog criada/verificada com sucesso."
  echo "🔁 Para aplicar as novas configurações, execute:"
  echo "    sudo systemctl reload rsyslog"
else
  error "Falha ao criar ou configurar a estrutura do Rsyslog."
  echo "⚠️  Verifique permissões e tente novamente."
fi
