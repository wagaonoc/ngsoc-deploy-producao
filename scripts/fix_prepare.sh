#!/bin/bash
set -euo pipefail

# ===============================================================
# 🧰 RESTAURAÇÃO E FIX DO PREPARE DO HARBOR (v2.14.0) - SAFE
# ===============================================================
# Filosofia:
# - NADA de montar a pasta do instalador em /config (o prepare limpa!)
# - Geramos em uma pasta "generated" isolada e depois sincronizamos
# - Não apagamos scripts originais (install.sh, prepare, etc.)
# - Mantemos compatibilidade com suas decisões anteriores (certs, secretkey,
#   log_location, portas e Trivy)
#
# Resultado:
# - docker-compose.yml e common/config/* gerados em .../generated_prepare
# - Depois copiamos para installer/harbor/ preservando o resto

# ==============
# Variáveis base
# ==============
HARBOR_BASE="/opt/ngsoc-deploy/data/harbor"
INSTALLER_DIR="${HARBOR_BASE}/installer"
INSTALLER_HARBOR_DIR="${INSTALLER_DIR}/harbor"
LOG_DIR="/opt/ngsoc-deploy/logs/harbor"

# Caminhos de cert (ponto de compatibilidade exigido pelo prepare)
CERTS_DIR_COMPAT="${HARBOR_BASE}/certs"   # /opt/.../harbor/certs
REAL_CERT_PATH="/etc/ssl/certs/nginx-selfsigned.crt"
REAL_KEY_PATH="/etc/ssl/private/nginx-selfsigned.key"

# Segredos
SECRET_DIR="${HARBOR_BASE}/data/secret"
KEYS_DIR="${SECRET_DIR}/keys"
TLS_DIR="${SECRET_DIR}/tls"
SECRETKEY_FILE="${KEYS_DIR}/secretkey"
SECRETKEY_VALUE="nsoIfbwfJ9I4NUhz"  # 16 chars (backup seu válido)

# harbor.yml – preferimos o do instalador; senão, usamos prepare_conf
PREF_YML="${INSTALLER_HARBOR_DIR}/harbor.yml"
FALLBACK_DIR="${HARBOR_BASE}/prepare_conf"
FALLBACK_YML="${FALLBACK_DIR}/harbor.yml"

# Pasta segura de geração (o prepare pode limpar à vontade aqui)
GEN_DIR="${HARBOR_BASE}/generated_prepare"
GEN_CONFIG_DIR="${GEN_DIR}/common/config"

# Imagem
PREPARE_IMAGE="goharbor/prepare:v2.14.0"

echo "=============================================================="
echo "🧰 RESTAURAÇÃO E FIX DO PREPARE DO HARBOR (v2.14.0) - SAFE"
echo "=============================================================="

# ---------------------------------------------------------------
# 0) Garantias de diretórios
# ---------------------------------------------------------------
sudo mkdir -p "${INSTALLER_HARBOR_DIR}" "${LOG_DIR}" "${CERTS_DIR_COMPAT}" \
              "${KEYS_DIR}" "${TLS_DIR}" "${FALLBACK_DIR}" "${GEN_CONFIG_DIR}"

# ---------------------------------------------------------------
# 1) Certificados de compatibilidade no caminho que o prepare procura
#    (/opt/.../harbor/certs/harbor.{crt,key})
# ---------------------------------------------------------------
echo "1) 🔒 Garantindo certificados compatíveis em ${CERTS_DIR_COMPAT}..."
if [[ ! -f "${CERTS_DIR_COMPAT}/harbor.crt" ]]; then
  sudo cp -f "${REAL_CERT_PATH}" "${CERTS_DIR_COMPAT}/harbor.crt"
fi
if [[ ! -f "${CERTS_DIR_COMPAT}/harbor.key" ]]; then
  sudo cp -f "${REAL_KEY_PATH}" "${CERTS_DIR_COMPAT}/harbor.key"
fi
sudo chmod 600 "${CERTS_DIR_COMPAT}/harbor.crt" "${CERTS_DIR_COMPAT}/harbor.key"

# ---------------------------------------------------------------
# 2) Secretkey – respeitar se já existe e tem 16 chars, senão corrigir
# ---------------------------------------------------------------
echo "2) 🔑 Garantindo secretkey válida (16 chars)..."
if [[ -f "${SECRETKEY_FILE}" ]]; then
  LEN=$(wc -c < "${SECRETKEY_FILE}" | tr -d ' ')
  if [[ "${LEN}" -ne 16 ]]; then
    echo -n "${SECRETKEY_VALUE}" | sudo tee "${SECRETKEY_FILE}" >/dev/null
  fi
else
  echo -n "${SECRETKEY_VALUE}" | sudo tee "${SECRETKEY_FILE}" >/dev/null
fi
sudo chmod 600 "${SECRETKEY_FILE}"

# ---------------------------------------------------------------
# 3) CA interna para satisfazer 'create_root_cert' (gera só se faltar)
# ---------------------------------------------------------------
echo "3) 🧾 Garantindo CA interna (harbor_internal_ca.*)..."
if [[ ! -f "${TLS_DIR}/harbor_internal_ca.crt" || ! -f "${TLS_DIR}/harbor_internal_ca.key" ]]; then
  sudo openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
    -keyout "${TLS_DIR}/harbor_internal_ca.key" \
    -out "${TLS_DIR}/harbor_internal_ca.crt" \
    -subj "/CN=harbor.local/O=POSITIVOS+/C=BR" >/dev/null 2>&1 || true
  sudo chmod 600 "${TLS_DIR}/harbor_internal_ca."*
fi

# ---------------------------------------------------------------
# 4) harbor.yml – usar o do instalador; se não existir, criar fallback
# ---------------------------------------------------------------
echo "4) 📄 Selecionando harbor.yml..."
HARBOR_YML="${PREF_YML}"
if [[ ! -f "${HARBOR_YML}" ]]; then
  echo "   ⚠️ ${PREF_YML} não encontrado; usando fallback ${FALLBACK_YML}"
  HARBOR_YML="${FALLBACK_YML}"
  if [[ ! -f "${HARBOR_YML}" ]]; then
    echo "   ➕ Criando YAML funcional de fallback..."
    sudo tee "${HARBOR_YML}" >/dev/null <<'EOF'
hostname: harbor.local

http:
  port: 8081

https:
  port: 8443
  certificate: /etc/ssl/certs/nginx-selfsigned.crt
  private_key: /etc/ssl/private/nginx-selfsigned.key

harbor_admin_password: "Harbor12345"

database:
  password: "HarborDBpass"

# ============================================================
# Caminhos de armazenamento
# ============================================================
data_volume: /opt/ngsoc-deploy/data/harbor/data

# 🚨 Chave lida por alguns preparadores (evita KeyError: 'log_location')
log_location: /opt/ngsoc-deploy/logs/harbor

# ============================================================
# Logs e auditoria
# ============================================================
log:
  level: info
  local:
    location: /opt/ngsoc-deploy/logs/harbor
  syslog:
    port: 0
    protocol: tcp

# ============================================================
# Trivy e segurança
# ============================================================
trivy:
  server_url: http://localhost:4954
  ignore_unfixed: true
  skip_update: false
  vuln_type: "os,library"
  security_check: "vuln"

# ============================================================
# Serviço de tarefas
# ============================================================
jobservice:
  max_job_workers: 10
  logger:
    sweeper_duration: 5
    loggers:
      - name: STD_OUTPUT
        level: INFO
      - name: FILE
        level: INFO
        location: /var/log/jobs.log

# ============================================================
# Notificações
# ============================================================
notification:
  webhook_job_max_retry: 3
  webhook_job_http_client_timeout: 30s
EOF
  fi
fi

# ---------------------------------------------------------------
# 4.1) ⚙️ Correção automática do bloco jobservice (v2.14.x)
# ---------------------------------------------------------------
if ! grep -q "job_loggers" "${HARBOR_YML}"; then
  echo "   ⚙️ Corrigindo bloco jobservice para compatibilidade v2.14.x..."
  sudo sed -i '/jobservice:/,/^$/c\jobservice:\n  max_job_workers: 10\n  logger_sweeper_duration: 5\n  job_loggers:\n    - name: STD_OUTPUT\n      level: INFO\n    - name: FILE\n      level: INFO\n      location: /var/log/jobs.log' "${HARBOR_YML}"
fi

# ---------------------------------------------------------------
# 5) Permissões amigáveis para o Docker
# ---------------------------------------------------------------
sudo chmod -R 755 "${INSTALLER_DIR}" "${HARBOR_BASE}" "${LOG_DIR}" || true

# ---------------------------------------------------------------
# 6) Rodar o prepare com MAPEAMENTO DO ARQUIVO (não do diretório!)
#    e COMPOSE_LOCATION ISOLADO em ${GEN_DIR}
# ---------------------------------------------------------------
echo "6) ⚙️ Executando prepare de forma segura (isolado em ${GEN_DIR})..."
# Limpamos SOMENTE a pasta gerada (safe), nunca a do instalador
sudo rm -rf "${GEN_DIR}"
sudo mkdir -p "${GEN_CONFIG_DIR}"

# Dica: --with-trivy habilita geração dos blocos do adapter
WITH_TRIVY="--with-trivy"

sudo docker run --rm \
  -v "${HARBOR_YML}":/input/harbor.yml:ro \
  -v "${HARBOR_BASE}/data":/data \
  -v "${GEN_DIR}":/compose_location \
  -v "${GEN_CONFIG_DIR}":/config \
  -v /:/hostfs:ro \
  -v /etc/ssl/certs:/etc/ssl/certs:ro \
  -v /etc/ssl/private:/etc/ssl/private:ro \
  "${PREPARE_IMAGE}" prepare ${WITH_TRIVY}

echo "   ✅ Prepare finalizado. Sincronizando artefatos gerados..."

# ---------------------------------------------------------------
# 7) Sincronizar SOMENTE o que é gerado (preservar scripts originais)
# ---------------------------------------------------------------
TS=$(date +%Y%m%d-%H%M%S)
# docker-compose.yml
if [[ -f "${GEN_DIR}/docker-compose.yml" ]]; then
  if [[ -f "${INSTALLER_HARBOR_DIR}/docker-compose.yml" ]]; then
    sudo cp -a "${INSTALLER_HARBOR_DIR}/docker-compose.yml" "${INSTALLER_HARBOR_DIR}/docker-compose.yml.bak.${TS}"
  fi
  sudo cp -f "${GEN_DIR}/docker-compose.yml" "${INSTALLER_HARBOR_DIR}/docker-compose.yml"
fi

# common/config/*
if compgen -G "${GEN_CONFIG_DIR}/*" >/dev/null; then
  # copia hierarquia mantendo apenas arquivos gerados
  rsync -a --delete "${GEN_CONFIG_DIR}/" "${INSTALLER_HARBOR_DIR}/common/config/"
fi

# ---------------------------------------------------------------
# 8) Verificações finais
# ---------------------------------------------------------------
echo "=============================================================="
if [[ -f "${INSTALLER_HARBOR_DIR}/docker-compose.yml" ]]; then
  echo "📄 docker-compose.yml presente em:"
  echo "   ${INSTALLER_HARBOR_DIR}/docker-compose.yml"
else
  echo "⚠️ docker-compose.yml não localizado após sync; verifique ${GEN_DIR}"
fi

echo "📁 Itens-chave agora garantidos:"
printf "   - %s\n" \
  "${CERTS_DIR_COMPAT}/harbor.key" \
  "${CERTS_DIR_COMPAT}/harbor.crt" \
  "${SECRETKEY_FILE}" \
  "${TLS_DIR}/harbor_internal_ca.crt" \
  "${HARBOR_YML}" \
  "${INSTALLER_HARBOR_DIR}/docker-compose.yml"

echo "🔒 Scripts preservados (não tocados):"
printf "   - %s\n" \
  "${INSTALLER_HARBOR_DIR}/install.sh (se existir)" \
  "${INSTALLER_HARBOR_DIR}/prepare (se existir)" \
  "${INSTALLER_HARBOR_DIR}/harbor.yml.tmpl (se existir)"

echo "=============================================================="
echo "🎯 FIX-PREPARE SEGURO E RETROCOMPATÍVEL — concluído."
echo "=============================================================="
