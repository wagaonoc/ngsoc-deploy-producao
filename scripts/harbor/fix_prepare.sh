#!/bin/bash
set -euo pipefail
# ===============================================================
# 🧰 RESTAURAÇÃO E FIX DO PREPARE DO HARBOR (v2.14.0) – FINAL UNIVERSAL REVISADO
# ===============================================================

HARBOR_BASE="/opt/ngsoc-deploy/data/harbor"
INSTALLER_DIR="${HARBOR_BASE}/installer"
INSTALLER_HARBOR_DIR="${INSTALLER_DIR}/harbor"
LOG_DIR="/opt/ngsoc-deploy/logs/harbor"
CERTS_DIR_COMPAT="${HARBOR_BASE}/certs"
REAL_CERT_PATH="/etc/ssl/certs/nginx-selfsigned.crt"
REAL_KEY_PATH="/etc/ssl/private/nginx-selfsigned.key"
SECRET_DIR="${HARBOR_BASE}/data/secret"
KEYS_DIR="${SECRET_DIR}/keys"
TLS_DIR="${SECRET_DIR}/tls"
SECRETKEY_FILE="${KEYS_DIR}/secretkey"
SECRETKEY_VALUE="nsoIfbwfJ9I4NUhz"
PREF_YML="${INSTALLER_HARBOR_DIR}/harbor.yml"
FALLBACK_DIR="${HARBOR_BASE}/prepare_conf"
FALLBACK_YML="${FALLBACK_DIR}/harbor.yml"
GEN_DIR="${HARBOR_BASE}/generated_prepare"
GEN_CONFIG_DIR="${GEN_DIR}/common/config"
PREPARE_IMAGE="goharbor/prepare:v2.14.0"

echo "=============================================================="
echo "🧰 RESTAURAÇÃO E FIX DO PREPARE DO HARBOR (v2.14.0)"
echo "=============================================================="

sudo mkdir -p "${INSTALLER_HARBOR_DIR}" "${LOG_DIR}" "${CERTS_DIR_COMPAT}" \
              "${KEYS_DIR}" "${TLS_DIR}" "${FALLBACK_DIR}" "${GEN_CONFIG_DIR}"

# ---------------------------------------------------------------
# 1️⃣ Certificados e Secretkey
# ---------------------------------------------------------------
echo "1️⃣ Garantindo certificados e segredos..."
sudo cp -n "${REAL_CERT_PATH}" "${CERTS_DIR_COMPAT}/harbor.crt" 2>/dev/null || true
sudo cp -n "${REAL_KEY_PATH}"  "${CERTS_DIR_COMPAT}/harbor.key"  2>/dev/null || true
sudo chmod 600 "${CERTS_DIR_COMPAT}/harbor."* || true
[[ ! -f "${SECRETKEY_FILE}" || "$(wc -c <"${SECRETKEY_FILE}" | tr -d ' ')" -ne 16 ]] && \
  echo -n "${SECRETKEY_VALUE}" | sudo tee "${SECRETKEY_FILE}" >/dev/null
sudo chmod 600 "${SECRETKEY_FILE}"

# ---------------------------------------------------------------
# 2️⃣ CA Interna
# ---------------------------------------------------------------
echo "2️⃣ Garantindo CA interna..."
if [[ ! -f "${TLS_DIR}/harbor_internal_ca.crt" ]]; then
  sudo openssl req -x509 -newkey rsa:2048 -days 365 -nodes \
    -keyout "${TLS_DIR}/harbor_internal_ca.key" \
    -out "${TLS_DIR}/harbor_internal_ca.crt" \
    -subj "/CN=harbor.local/O=POSITIVOS+/C=BR" >/dev/null 2>&1 || true
  sudo chmod 600 "${TLS_DIR}"/* || true
fi

# ---------------------------------------------------------------
# 3️⃣ Seleção do harbor.yml
# ---------------------------------------------------------------
echo "3️⃣ Selecionando harbor.yml..."
HARBOR_YML="${PREF_YML}"
if [[ ! -f "${HARBOR_YML}" ]]; then
  echo "   ⚠️ ${PREF_YML} não encontrado; criando fallback..."
  sudo mkdir -p "$(dirname "${FALLBACK_YML}")"
  HARBOR_YML="${FALLBACK_YML}"
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
data_volume: /opt/ngsoc-deploy/data/harbor/data
log_location: /opt/ngsoc-deploy/logs/harbor
log:
  level: info
  local:
    location: /opt/ngsoc-deploy/logs/harbor
  syslog:
    port: 0
    protocol: tcp
trivy:
  server_url: http://localhost:4954
  ignore_unfixed: true
  skip_update: false
  vuln_type: "os,library"
  security_check: "vuln"
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
EOF
fi

# ---------------------------------------------------------------
# 4️⃣ Corrigir jobservice
# ---------------------------------------------------------------
echo "4️⃣ Corrigindo bloco 'jobservice'..."
sudo sed -i '/^jobservice:/,/^$/{
  /^jobservice:/!d
  i\jobservice:\n  max_job_workers: 10\n  logger_sweeper_duration: 1\n  job_loggers:\n    - file\n    - stdout
  d
}' "${HARBOR_YML}"

# ---------------------------------------------------------------
# 5️⃣ Recriar bloco notification no formato esperado
# ---------------------------------------------------------------
echo "5️⃣ Corrigindo bloco 'notification'..."
if grep -q "^notification:" "${HARBOR_YML}"; then
  echo "   🧹 Removendo bloco 'notification:' existente..."
  sudo sed -i '/^notification:/,/^[^[:space:]]/d' "${HARBOR_YML}"
fi

sudo tee -a "${HARBOR_YML}" >/dev/null <<'EOF'

# ============================================================
# Bloco compatível com prepare v2.14.0
# ============================================================
notification:
  webhook_job_max_retry: 3
  webhook_job_http_client_timeout: 30s
EOF

echo "   🔍 Verificação final do bloco 'notification':"
grep -A2 "notification:" "${HARBOR_YML}" || echo "   ⚠️ Bloco não encontrado — verifique manualmente."

# ---------------------------------------------------------------
# 6️⃣ Limpeza de resíduos de execuções anteriores
# ---------------------------------------------------------------
echo "6️⃣ Limpando resíduos de execuções anteriores..."
sudo docker ps -a --format '{{.ID}} {{.Image}}' | grep 'goharbor/prepare' | awk '{print $1}' | xargs -r sudo docker rm -f >/dev/null 2>&1 || true
sudo rm -rf "${GEN_DIR}"
sudo mkdir -p "${GEN_CONFIG_DIR}"

# ---------------------------------------------------------------
# 7️⃣ Executar prepare
# ---------------------------------------------------------------
echo "7️⃣ Executando prepare (isolado e seguro)..."
WITH_TRIVY="--with-trivy"

sudo docker run --rm \
  -v "${HARBOR_YML}":/input/harbor.yml:ro \
  -v "${HARBOR_BASE}/data":/data \
  -v "${GEN_DIR}":/compose_location \
  -v "${GEN_CONFIG_DIR}":/config \
  -v /:/hostfs:ro \
  -v /etc/ssl/certs:/etc/ssl/certs:ro \
  -v /etc/ssl/private:/etc/ssl/private:ro \
  "${PREPARE_IMAGE}" prepare ${WITH_TRIVY} || {
    echo "❌ Falha ao executar prepare."
    exit 1
  }

# ---------------------------------------------------------------
# 8️⃣ Sincronização segura
# ---------------------------------------------------------------
TS=$(date +%Y%m%d-%H%M%S)
COMPOSE_FILE="${INSTALLER_HARBOR_DIR}/docker-compose.yml"
if [[ -f "${GEN_DIR}/docker-compose.yml" ]]; then
  [[ -f "${COMPOSE_FILE}" ]] && sudo cp -a "${COMPOSE_FILE}" "${COMPOSE_FILE}.bak.${TS}"
  sudo cp -f "${GEN_DIR}/docker-compose.yml" "${COMPOSE_FILE}"
fi
if compgen -G "${GEN_CONFIG_DIR}/*" >/dev/null; then
  rsync -a --delete "${GEN_CONFIG_DIR}/" "${INSTALLER_HARBOR_DIR}/common/config/"
fi

# ---------------------------------------------------------------
# 🧩 FIX PORTA 1514 – Remoção para evitar conflito com Wazuh
# ---------------------------------------------------------------
if [[ -f "${COMPOSE_FILE}" ]]; then
  echo "🧩 Removendo mapeamento de porta 1514 (conflito com Wazuh)..."
  sudo sed -i '/1514/d' "${COMPOSE_FILE}"
  sudo sed -i '/10514/d' "${COMPOSE_FILE}"
  echo "   ✅ Portas 1514 e 10514 removidas do docker-compose.yml com sucesso."
  echo "   🧾 Logs continuarão sendo gravados em /opt/ngsoc-deploy/logs/harbor"
fi

# ---------------------------------------------------------------
# 🧱 Neutralizar rsyslog interno (porta 10514)
# ---------------------------------------------------------------
LOG_CONF_FILE="${INSTALLER_HARBOR_DIR}/common/config/log/rsyslog_docker.conf"
LOG_MAIN_FILE="${INSTALLER_HARBOR_DIR}/common/config/log/log.conf"
if [[ -f "${LOG_CONF_FILE}" ]]; then
  sudo sed -i 's/^input(type="imtcp" port="10514")/# desativado: conflito Wazuh/' "${LOG_CONF_FILE}"
fi
if [[ -f "${LOG_MAIN_FILE}" ]]; then
  sudo sed -i '/10514/d' "${LOG_MAIN_FILE}"
fi
echo "   ✅ Porta 10514 desativada no rsyslog interno do Harbor."





# ---------------------------------------------------------------
# 9️⃣ Correção estrutural do bloco 'services.log.volumes' (INSERÇÃO SIMPLES - FINAL)
# ---------------------------------------------------------------
if [[ -f "${COMPOSE_FILE}" ]]; then
  echo "🧱 Corrigindo estrutura de volumes do serviço 'log' (INSERÇÃO SIMPLES)..."

  # 1️⃣ Remove quaisquer volumes antigos de log que possam ter sido injetados anteriormente
  sudo sed -i '/common\/config\/log\/logrotate.conf/d' "${COMPOSE_FILE}"
  sudo sed -i '/common\/config\/log\/rsyslog_docker.conf/d' "${COMPOSE_FILE}"
  sudo sed -i '/\/opt\/ngsoc-deploy\/logs\/harbor\/:/d' "${COMPOSE_FILE}"

  # 2️⃣ Injeta os binds corretos logo abaixo de 'volumes:' no serviço log
  TMP_FIX="${COMPOSE_FILE}.tmp_fixlog"
  awk '
    /^  log:$/ {in_log=1}
    in_log && /^    volumes:$/ {
      print
      print "      - ./common/config/log/logrotate.conf:/etc/logrotate.d/logrotate.conf:ro"
      print "      - ./common/config/log/rsyslog_docker.conf:/etc/rsyslog.d/rsyslog_docker.conf:ro"
      print "      - /opt/ngsoc-deploy/logs/harbor/:/var/log/docker/:z"
      in_log=0; next
    }
    {print}
  ' "${COMPOSE_FILE}" > "${TMP_FIX}"

  sudo mv "${TMP_FIX}" "${COMPOSE_FILE}"
  echo "   ✅ Bloco 'services.log.volumes' corrigido com inserção simples."
fi







# ---------------------------------------------------------------
# 🧩 Normalização robusta do serviço 'log' → ports: []
# ---------------------------------------------------------------
if [[ -f "${COMPOSE_FILE}" ]]; then
  echo "🛠️  Normalizando 'services.log.ports' para array YAML..."
  sudo awk '
    BEGIN{in_log=0; in_hlog=0}
    /^services:/ {print; next}
    /^  log:$/    {in_log=1; print; next}
    /^  harbor-log:$/ {in_hlog=1; print; next}
    (in_log || in_hlog) {
      if ($0 ~ /^    ports:/) { print "____PORTS_PLACEHOLDER____"; next }
      if ($0 ~ /^      - /)   { next }
      if ($0 ~ /^  [a-zA-Z0-9_-]+:/) {
        print "    ports: []"
        in_log=0; in_hlog=0
      }
      print; next
    }
    {print}
  ' "${COMPOSE_FILE}" | sudo tee "${COMPOSE_FILE}.tmp1" >/dev/null
  sudo sed -i 's/^____PORTS_PLACEHOLDER____$/    ports: []/' "${COMPOSE_FILE}.tmp1"
  sudo mv "${COMPOSE_FILE}.tmp1" "${COMPOSE_FILE}"
  echo "   ✅ services.log(.|)ports normalizado."
fi


# ---------------------------------------------------------------
# 🔧 Remover duplicações de 'ports'
# ---------------------------------------------------------------
if [[ -f "${COMPOSE_FILE}" ]]; then
  echo "🧹 Corrigindo duplicações de 'ports:' dentro do docker-compose.yml..."
  sudo awk '
    BEGIN {ports_seen=0}
    {
      if ($0 ~ /^    ports:/) {
        if (ports_seen==0) { print; ports_seen=1; next } else next
      }
      if ($0 ~ /^  [a-zA-Z0-9_-]+:/) { ports_seen=0 }
      print
    }
  ' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_cleanports"
  sudo mv "${COMPOSE_FILE}.tmp_cleanports" "${COMPOSE_FILE}"
  echo "   ✅ Duplicações de 'ports:' removidas com sucesso."
fi

# ---------------------------------------------------------------
# 🧩 Corrigir formato 'networks' (log/harbor-log)
# ---------------------------------------------------------------
if [[ -f "${COMPOSE_FILE}" ]]; then
  echo "🧩 Corrigindo formato de 'networks:' nos serviços log/harbor-log..."
  sudo awk '
    BEGIN {in_log=0; in_hlog=0}
    /^  log:$/ {in_log=1; print; next}
    /^  harbor-log:$/ {in_hlog=1; print; next}
    (in_log || in_hlog) {
      if ($0 ~ /^    networks:/) {
        print "    networks:"
        print "      - harbor"
        next
      }
      if ($0 ~ /^  [a-zA-Z0-9_-]+:/) {in_log=0; in_hlog=0}
    }
    {print}
  ' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_networksfix"
  sudo mv "${COMPOSE_FILE}.tmp_networksfix" "${COMPOSE_FILE}"
  echo "   ✅ Formato de 'networks:' corrigido para array com sucesso."
fi

# ---------------------------------------------------------------
# 🧩 Recriar blocos cap_drop/cap_add no formato funcional
# ---------------------------------------------------------------
if [[ -f "${COMPOSE_FILE}" ]]; then
  echo "🧩 Recriando blocos cap_drop e cap_add com listas válidas..."
  sudo sed -i '/^    cap_drop:/,/^    cap_add:/c\    cap_drop:\n      - ALL\n    cap_add:\n      - CHOWN\n      - DAC_OVERRIDE\n      - SETGID\n      - SETUID' "${COMPOSE_FILE}"
  echo "   ✅ cap_drop/cap_add reconstruídos no formato de lista (compatível com Compose)."
fi

# ---------------------------------------------------------------
# 🔎 Conferência visual
# ---------------------------------------------------------------
if [[ -f "${COMPOSE_FILE}" ]]; then
  echo "——— Trecho atual do serviço log/harbor-log ———"
  nl -ba "${COMPOSE_FILE}" | sed -n '/^ *[0-9]\+  *  log:$/,/^ *[0-9]\+  *  [a-zA-Z0-9_-]\+:$/p' || true
  nl -ba "${COMPOSE_FILE}" | sed -n '/^ *[0-9]\+  *  harbor-log:$/,/^ *[0-9]\+  *  [a-zA-Z0-9_-]\+:$/p' || true
  echo "———————————————————————————————————————————————"
fi

# =================================================================
# 🔗 (ACRÉSCIMO) Rede padrão ngsoc_net – sem remover nada anterior
# =================================================================
if [[ -f "${COMPOSE_FILE}" ]]; then
  echo "🌐 Ajustando rede para usar 'ngsoc_net' como rede padrão externa (preservando correções)..."
  sudo sed -i 's/^\([[:space:]]*\)-[[:space:]]*harbor$/\1- default/' "${COMPOSE_FILE}" || true
  awk '
    BEGIN {innet=0}
    /^networks:[[:space:]]*$/ {innet=1; next}
    innet && /^[^[:space:]]/ {innet=0}
    !innet {print}
  ' "${COMPOSE_FILE}" | sudo tee "${COMPOSE_FILE}.tmp_netdefault" >/dev/null
  sudo mv "${COMPOSE_FILE}.tmp_netdefault" "${COMPOSE_FILE}"

  # 🔧 Correção idempotente: não recriar bloco networks se já existir com ngsoc_net
  if ! grep -q "name: ngsoc_net" "${COMPOSE_FILE}"; then
    if ! grep -qE 'networks:[[:space:]]*$' "${COMPOSE_FILE}" || ! grep -q "ngsoc_net" "${COMPOSE_FILE}"; then
      sudo tee -a "${COMPOSE_FILE}" >/dev/null <<'EOF'

networks:
  default:
    external: true
    name: ngsoc_net
EOF
    else
      echo "   ⚙️ Bloco 'networks' já existente, não será recriado (idempotente)."
    fi
  else
    echo "   ⚙️ Bloco 'networks' com 'ngsoc_net' já presente — nenhuma ação necessária."
  fi

  echo "   ✅ Rede default -> ngsoc_net configurada."
fi

# =================================================================
# 🗂️ (ACRÉSCIMO) Logs via volume (idempotente)
# =================================================================
if [[ -f "${COMPOSE_FILE}" ]]; then
  echo "🗂️ Garantindo exportação de logs via volume para /opt/ngsoc-deploy/logs/harbor (sem 1514)..."
  sudo awk -v bind="      - /opt/ngsoc-deploy/logs/harbor/:/var/log/docker/:z" '
    BEGIN {inlog=0; inv=0; has=0}
    /^  log:$/ {inlog=1; print; next}
    inlog && /^    volumes:/ {inv=1; print; next}
    inlog && inv && $0 ~ /^[[:space:]]*-[[:space:]]*\/opt\/ngsoc-deploy\/logs\/harbor\/:\/var\/log\/docker\/:z/ {has=1}
    inlog && inv && ($0 ~ /^  [a-zA-Z0-9_-]+:/) {
      if (!has) print bind
      inlog=0; inv=0; has=0
    }
    {print}
    END { if (inlog && inv && !has) print bind }
  ' "${COMPOSE_FILE}" | sudo tee "${COMPOSE_FILE}.tmp_logbind" >/dev/null
  sudo mv "${COMPOSE_FILE}.tmp_logbind" "${COMPOSE_FILE}"
  echo "   ✅ Bind de logs garantido no serviço 'log'."
fi

# ---------------------------------------------------------------
# 🧩 FIX FINAL: corrigir referências residuais à rede 'harbor'
# ---------------------------------------------------------------
if [[ -f "${COMPOSE_FILE}" ]]; then
  echo "🧩 Corrigindo serviços que ainda referenciam a rede 'harbor'..."
  sudo sed -i 's/^\([[:space:]]*\)harbor:[[:space:]]*$/\1default:/' "${COMPOSE_FILE}" || true
  sudo sed -i 's/^[[:space:]]*-[[:space:]]*harbor$/      - default/' "${COMPOSE_FILE}" || true
  awk '
    BEGIN {innet=0; seen=0}
    /^networks:[[:space:]]*$/ {
      if (seen==0) { seen=1; print; innet=1; next } else { innet=1; next }
    }
    innet && /^[^[:space:]]/ {innet=0}
    { if (!innet) { print } }
  ' "${COMPOSE_FILE}" | sudo tee "${COMPOSE_FILE}.tmp_harborfix" >/dev/null
  sudo mv "${COMPOSE_FILE}.tmp_harborfix" "${COMPOSE_FILE}"

  # ⚙️ Correção idempotente de criação de bloco networks
  if ! grep -q "name: ngsoc_net" "${COMPOSE_FILE}"; then
    if ! grep -qE 'networks:[[:space:]]*$' "${COMPOSE_FILE}" || ! grep -q "ngsoc_net" "${COMPOSE_FILE}"; then
      sudo tee -a "${COMPOSE_FILE}" >/dev/null <<'EOF'

networks:
  default:
    external: true
    name: ngsoc_net
EOF
    else
      echo "   ⚙️ Bloco 'networks' já existente, não será recriado (idempotente)."
    fi
  else
    echo "   ⚙️ Bloco 'networks' com 'ngsoc_net' já presente — nenhuma ação necessária."
  fi

  echo "   ✅ Todas as referências à rede 'harbor' foram substituídas por 'ngsoc_net'."
fi

# ---------------------------------------------------------------
# 🧩 FIX EXTRA 1: normalizar 'networks:' de todos os serviços
# ---------------------------------------------------------------
if [[ -f "${COMPOSE_FILE}" ]]; then
  echo "🧩 Normalizando 'networks:' → lista ('- default') em todos os serviços..."
  sudo awk '
    BEGIN {in_service=0; in_net=0}
    /^  [a-zA-Z0-9_-]+:$/ {in_service=1; in_net=0; print; next}
    in_service && /^    networks:$/ {in_net=1; print; next}
    in_net && /^[[:space:]]*default:[[:space:]]*$/ { print "      - default"; in_net=0; next }
    in_net && /^      [a-zA-Z0-9_-]+:$/ { sub(/^[[:space:]]*[a-zA-Z0-9_-]+:/,"      - default",$0); in_net=0 }
    {print}
  ' "${COMPOSE_FILE}" | sudo tee "${COMPOSE_FILE}.tmp_netarray" >/dev/null
  sudo mv "${COMPOSE_FILE}.tmp_netarray" "${COMPOSE_FILE}"
  echo "   ✅ Todos os serviços usam formato de lista para 'networks:'."
fi

# ---------------------------------------------------------------
# 🧩 FIX EXTRA 2: reconstruir blocos de logging
# ---------------------------------------------------------------
if [[ -f "${COMPOSE_FILE}" ]]; then
  echo "🧩 Limpando '- default' indevido sob 'logging:' e reconstruindo blocos de logging..."
  sudo awk '
    BEGIN {in_logging=0}
    /^    logging:$/ {in_logging=1; print; next}
    in_logging && /^[[:space:]]*-[[:space:]]*default[[:space:]]*$/ { next }
    in_logging && /^  [a-zA-Z0-9_-]+:$/ { in_logging=0; print; next }
    { print }
  ' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_logdrop"
  sudo mv "${COMPOSE_FILE}.tmp_logdrop" "${COMPOSE_FILE}"

  sudo awk '
    function flush_logging() {
      if (pending_logging==1) {
        print "    logging:"
        print "      driver: \"syslog\""
        print "      options:"
        print "        tag: \"" current_service "\""
        pending_logging=0
      }
    }
    BEGIN {in_service=0; current_service=""; in_logging=0; pending_logging=0}
    /^  [a-zA-Z0-9_-]+:$/ {
      flush_logging()
      in_service=1
      in_logging=0
      pending_logging=0
      line=$0
      sub(/^  /,"",line)
      sub(/:$/,"",line)
      current_service=line
      print
      next
    }
    in_service && /^    logging:$/ {
      in_logging=1
      pending_logging=1
      next
    }
    in_logging {
      if ($0 ~ /^    [a-z]/) { next }
      if ($0 ~ /^      /)    { next }
    }
    /^    [a-zA-Z0-9_-]+:/ {
      if (pending_logging==1) {
        flush_logging()
      }
      in_logging=0
      print
      next
    }
    /^  [a-zA-Z0-9_-]+:/ {
      flush_logging()
      in_logging=0
      in_service=1
      print
      next
    }
    END { flush_logging() }
    { print }
  ' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_logrebuild"
  sudo mv "${COMPOSE_FILE}.tmp_logrebuild" "${COMPOSE_FILE}"
  echo "   ✅ Blocos de logging padronizados (driver syslog + tag do serviço)."
fi

# ---------------------------------------------------------------
# 🧩 FIX DEFINITIVO — Remover duplicações de 'networks:' antes da validação
# ---------------------------------------------------------------
if [[ -f "${COMPOSE_FILE}" ]]; then
  echo "🧩 Eliminando duplicações de 'networks:' antes da validação..."
  TMP_FINAL="${COMPOSE_FILE}.tmp_netclean"

  # Remove blocos duplicados "networks:" globais, mantendo apenas o primeiro
  sudo awk '
    BEGIN {in_net=0; net_seen=0}
    /^networks:[[:space:]]*$/ {
      net_seen++;
      if (net_seen>1) {in_net=1; next}   # descarta blocos networks: subsequentes
      next                                # preserva o primeiro "networks:" mas sem imprimir a linha ainda
    }
    in_net && /^[^[:space:]]/ {in_net=0}  # sai do bloco descartado ao ver nova top-level key
    { if (!in_net) print }                # imprime tudo que não está em bloco descartado
  ' "${COMPOSE_FILE}" > "${TMP_FINAL}"

  # Remove linhas "networks:" sozinhas (evita sobra de cabeçalho vazio)
  sudo sed -i '/^networks:[[:space:]]*$/d' "${TMP_FINAL}"

  # Garante que exista um único bloco final válido de networks → ngsoc_net
  if ! grep -q "name: ngsoc_net" "${TMP_FINAL}"; then
    sudo tee -a "${TMP_FINAL}" >/dev/null <<'EOF'

networks:
  default:
    external: true
    name: ngsoc_net
EOF
  fi

  sudo mv "${TMP_FINAL}" "${COMPOSE_FILE}"
  echo "   ✅ Duplicações de 'networks:' removidas; bloco final único e válido (ngsoc_net)."
fi



# ---------------------------------------------------------------
# 🧩 Verificando e corrigindo volumes de registry e registryctl
# ---------------------------------------------------------------
if [[ -f "${COMPOSE_FILE}" ]]; then
  echo "🧩 Verificando volumes de registry e registryctl..."

  # --- Garantir volumes corretos do serviço 'registry' ---
  if ! grep -q "./common/config/registry/config.yml:/etc/registry/config.yml" "${COMPOSE_FILE}"; then
    echo "   ➕ Corrigindo volumes do serviço 'registry'..."
    sudo awk '
      BEGIN {in_service=0; in_vol=0; done=0}
      /^  registry:$/ {in_service=1; print; next}
      in_service && /^    volumes:/ {in_vol=1; print; next}
      in_service && in_vol && $0 ~ /^    [a-zA-Z]/ {in_vol=0}
      {
        if (in_service && in_vol && done==0 && $0 ~ /^    [a-zA-Z]/) {
          print "      - ./common/config/registry/config.yml:/etc/registry/config.yml:ro"
          print "      - ./common/config/registry/passwd:/etc/registry/passwd:ro"
          print "      - /opt/ngsoc-deploy/data/harbor/data/registry:/storage"
          done=1
        }
        print
      }
    ' "${COMPOSE_FILE}" | sudo tee "${COMPOSE_FILE}.tmp_registry" >/dev/null
    sudo mv "${COMPOSE_FILE}.tmp_registry" "${COMPOSE_FILE}"
    echo "   ✅ Volumes de registry corrigidos."
  else
    echo "   ⚙️ Volumes de registry já corretos — nenhuma alteração necessária."
  fi

  # --- Garantir volumes corretos do serviço 'registryctl' ---
  if ! grep -q "./common/config/registryctl/config.yml:/etc/registryctl/config.yml" "${COMPOSE_FILE}"; then
    echo "   ➕ Corrigindo volumes do serviço 'registryctl'..."
    sudo awk '
      BEGIN {in_service=0; in_vol=0; done=0}
      /^  registryctl:$/ {in_service=1; print; next}
      in_service && /^    volumes:/ {in_vol=1; print; next}
      in_service && in_vol && $0 ~ /^    [a-zA-Z]/ {in_vol=0}
      {
        if (in_service && in_vol && done==0 && $0 ~ /^    [a-zA-Z]/) {
          print "      - ./common/config/registryctl/config.yml:/etc/registryctl/config.yml:ro"
          print "      - ./common/config/registry:/etc/registry:ro"
          done=1
        }
        print
      }
    ' "${COMPOSE_FILE}" | sudo tee "${COMPOSE_FILE}.tmp_registryctl" >/dev/null
    sudo mv "${COMPOSE_FILE}.tmp_registryctl" "${COMPOSE_FILE}"
    echo "   ✅ Volumes de registryctl corrigidos."
  else
    echo "   ⚙️ Volumes de registryctl já corretos — nenhuma alteração necessária."
  fi

  echo "   ✅ Correções de volumes concluídas."
fi


# ---------------------------------------------------------------
# 🧩 Correções finais de permissões, binds e ajustes de volumes
# ---------------------------------------------------------------
echo "🧩 Aplicando correções finais de runtime e permissões..."

# ===============================================================
# 1️⃣ Corrigir permissões e diretórios críticos (registry, nginx, portal)
# ===============================================================
for dir in \
  "/opt/ngsoc-deploy/data/harbor/installer/harbor/common/config/registry" \
  "/opt/ngsoc-deploy/data/harbor/installer/harbor/common/config/registryctl" \
  "/opt/ngsoc-deploy/data/harbor/installer/harbor/common/config/nginx" \
  "/opt/ngsoc-deploy/data/harbor/installer/harbor/common/config/portal"
do
  sudo mkdir -p "$dir"
  sudo chown -R 10000:10000 "$dir"
done

# Diretório temporário para o Nginx interno do portal
if [[ ! -d "/var/run/harbor-portal" ]]; then
  sudo mkdir -p /var/run/harbor-portal
  sudo chmod 777 /var/run/harbor-portal
fi

echo "   ✅ Permissões e diretórios ajustados."

# ===============================================================
# 2️⃣ Corrigir montagem do serviço 'harbor-db' (mapeamento incorreto)
# ===============================================================
if grep -q "./common/config/db:/var/lib/postgresql/data" "${COMPOSE_FILE}"; then
  echo "🧩 Corrigindo mapeamento de volume do 'harbor-db'..."
  sudo sed -i 's#./common/config/db:/var/lib/postgresql/data#./common/config/db:/data#g' "${COMPOSE_FILE}"
  echo "   ✅ Volume do harbor-db corrigido para /data."
else
  echo "   ⚙️ Volume do harbor-db já está correto — nenhuma alteração necessária."
fi




# ===============================================================
# 🧩 Reconstrução completa dos volumes críticos de Harbor (baseado no compose funcional original)
# ===============================================================
echo "🧩 Injetando volumes essenciais de configuração (registry, registryctl, proxy, portal, core, jobservice, trivy)..."

declare -A binds=(
  # registry
  ["registry"]="./common/config/registry/:/etc/registry/:z"
  # registryctl
  ["registryctl"]="./common/config/registryctl/config.yml:/etc/registryctl/config.yml"
  # proxy (nginx principal)
  ["proxy"]="./common/config/nginx:/etc/nginx:z;/opt/ngsoc-deploy/data/harbor/data/secret/cert:/etc/cert:z"
  # portal (frontend nginx)
  ["portal"]="./common/config/portal/nginx.conf:/etc/nginx/nginx.conf"
  # core (backend principal)
  ["core"]="./common/config/core/app.conf:/etc/core/app.conf;/opt/ngsoc-deploy/data/harbor/data/secret/core/private_key.pem:/etc/core/private_key.pem;/opt/ngsoc-deploy/data/harbor/data/secret/keys/secretkey:/etc/core/key;/opt/ngsoc-deploy/data/harbor/data/ca_download/:/etc/core/ca/:z"
  # jobservice
  ["jobservice"]="./common/config/jobservice/config.yml:/etc/jobservice/config.yml;/opt/ngsoc-deploy/data/harbor/data/job_logs:/var/log/jobs:z"
  # trivy-adapter
  ["trivy-adapter"]="/opt/ngsoc-deploy/data/harbor/data/trivy-adapter/trivy:/home/scanner/.cache/trivy;/opt/ngsoc-deploy/data/harbor/data/trivy-adapter/reports:/home/scanner/.cache/reports"
)

for svc in "${!binds[@]}"; do
  IFS=';' read -ra vols <<< "${binds[$svc]}"
  for v in "${vols[@]}"; do
    if ! grep -q "$v" "$COMPOSE_FILE"; then
      echo "   ➕ Adicionando volume '$v' em '$svc'..."
      sudo awk -v srv="$svc" -v vol="$v" '
        BEGIN {in_service=0; in_vol=0; done=0}
        $0 ~ "^  "srv":" {in_service=1; print; next}
        in_service && /^    volumes:/ {in_vol=1; print; next}
        in_service && in_vol && /^    [a-zA-Z]/ {in_vol=0}
        {
          if (in_service && in_vol && done==0 && $0 ~ /^    [a-zA-Z]/) {
            print "      - " vol
            done=1
          }
          print
        }
      ' "$COMPOSE_FILE" | sudo tee "${COMPOSE_FILE}.tmp_${svc}" >/dev/null
      sudo mv "${COMPOSE_FILE}.tmp_${svc}" "$COMPOSE_FILE"
    fi
  done
done

echo "   ✅ Volumes essenciais injetados com sucesso."
# ===============================================================
# 🧾 Ajustando permissões de diretórios e certificados
# ===============================================================
for dir in registry registryctl core portal proxy jobservice trivy-adapter; do
  sudo mkdir -p "/opt/ngsoc-deploy/data/harbor/installer/harbor/common/config/$dir"
  sudo chown -R 10000:10000 "/opt/ngsoc-deploy/data/harbor/installer/harbor/common/config/$dir"
done
sudo chmod -R 755 /opt/ngsoc-deploy/data/harbor/installer/harbor/common/config
echo "   ✅ Estrutura e permissões normalizadas (UID 10000)."






# ===============================================================
# 🧩 Correções finais: caminhos absolutos e permissões de runtime
# ===============================================================
echo "🧩 Aplicando correções finais de path e permissões..."

COMPOSE_FILE="/opt/ngsoc-deploy/data/harbor/installer/harbor/docker-compose.yml"
COMMON_CFG="/opt/ngsoc-deploy/data/harbor/installer/harbor/common/config"
RUNTIME_DIR="/opt/ngsoc-deploy/data/harbor/runtime"

# --- Garante paths absolutos no docker-compose ---
sed -i "s#\./common/config/registry/#${COMMON_CFG}/registry/#g" "$COMPOSE_FILE"
sed -i "s#\./common/config/registryctl/config.yml#${COMMON_CFG}/registryctl/config.yml#g" "$COMPOSE_FILE"
sed -i "s#\./common/config/nginx#${COMMON_CFG}/nginx#g" "$COMPOSE_FILE"
sed -i "s#\./common/config/portal/nginx.conf#${COMMON_CFG}/portal/nginx.conf#g" "$COMPOSE_FILE"
sed -i "s#\./common/config/core/app.conf#${COMMON_CFG}/core/app.conf#g" "$COMPOSE_FILE"
sed -i "s#\./common/config/jobservice/config.yml#${COMMON_CFG}/jobservice/config.yml#g" "$COMPOSE_FILE"
sed -i "s#\./common/config/shared/trust-certificates#${COMMON_CFG}/shared/trust-certificates#g" "$COMPOSE_FILE"

# --- Cria diretórios de runtime (para nginx e portal) ---
mkdir -p "${RUNTIME_DIR}/nginx_temp" "${RUNTIME_DIR}/portal_run"
chown -R root:root "${RUNTIME_DIR}"
chmod -R 777 "${RUNTIME_DIR}"

# --- Injeta binds adicionais sem duplicar blocos de volumes ---
if ! grep -q "/etc/nginx/client_body_temp" "$COMPOSE_FILE"; then
  echo "➕ Injetando diretório temporário do nginx..."
  awk -v mount="${RUNTIME_DIR}/nginx_temp:/etc/nginx/client_body_temp" '
    $0 ~ /image: goharbor\/nginx-photon/ { in_nginx=1 }
    in_nginx && /volumes:/ { print; print "      - " mount; in_nginx=0; next }
    { print }
  ' "$COMPOSE_FILE" > "${COMPOSE_FILE}.tmp" && mv "${COMPOSE_FILE}.tmp" "$COMPOSE_FILE"
fi

if ! grep -q "/var/run" "$COMPOSE_FILE"; then
  echo "➕ Injetando diretório de execução do portal..."
  awk -v mount="${RUNTIME_DIR}/portal_run:/var/run" '
    $0 ~ /container_name: harbor-portal/ { in_portal=1 }
    in_portal && /volumes:/ { print; print "      - " mount; in_portal=0; next }
    { print }
  ' "$COMPOSE_FILE" > "${COMPOSE_FILE}.tmp" && mv "${COMPOSE_FILE}.tmp" "$COMPOSE_FILE"
fi

# --- Ajusta permissões de leitura global nos diretórios de config ---
chmod -R 755 "${COMMON_CFG}"
chown -R root:root "${COMMON_CFG}"

echo "✅ Caminhos absolutos e permissões corrigidos com sucesso."

# ===============================================================
# 🧩 Correção de permissões para registry e registryctl
# ===============================================================
echo "🧩 Ajustando permissões de arquivos críticos do registry e registryctl..."

COMMON_CFG="/opt/ngsoc-deploy/data/harbor/installer/harbor/common/config"

# Aplica dono UID 10000 (usuário interno do Harbor) e restringe leitura
if [ -d "${COMMON_CFG}/registry" ]; then
  chown -R 10000:10000 "${COMMON_CFG}/registry"
  chmod 640 "${COMMON_CFG}/registry/"*.yml "${COMMON_CFG}/registry/"*.conf 2>/dev/null || true
fi

if [ -d "${COMMON_CFG}/registryctl" ]; then
  chown -R 10000:10000 "${COMMON_CFG}/registryctl"
  chmod 640 "${COMMON_CFG}/registryctl/"*.yml "${COMMON_CFG}/registryctl/"*.conf 2>/dev/null || true
fi

echo "✅ Permissões ajustadas (UID 10000, leitura restrita)."





# ===============================================================
# 🧩 Correção de bind paths absolutos para registry e registryctl
# ===============================================================
echo "🧩 Garantindo bind paths absolutos para registry e registryctl..."

COMPOSE_FILE="/opt/ngsoc-deploy/data/harbor/installer/harbor/docker-compose.yml"
COMMON_CFG="/opt/ngsoc-deploy/data/harbor/installer/harbor/common/config"

# Substitui binds relativos por absolutos
if [ -f "$COMPOSE_FILE" ]; then
  sed -i "s#\./common/config/registryctl/#${COMMON_CFG}/registryctl/#g" "$COMPOSE_FILE"
  sed -i "s#\./common/config/registry/#${COMMON_CFG}/registry/#g" "$COMPOSE_FILE"
  echo "✅ Caminhos absolutos aplicados para registry e registryctl."
else
  echo "⚠️ docker-compose.yml não encontrado para aplicar paths absolutos."
fi



# ===============================================================
# 🧩 Removendo binds redundantes de config.yml para registry e registryctl
# ===============================================================
echo "🧩 Removendo binds duplicados de arquivo individual (config.yml)..."

COMPOSE_FILE="/opt/ngsoc-deploy/data/harbor/installer/harbor/docker-compose.yml"

if [ -f "$COMPOSE_FILE" ]; then
  sed -i '/common\/config\/registryctl\/config.yml/d' "$COMPOSE_FILE"
  sed -i '/common\/config\/registry\/config.yml/d' "$COMPOSE_FILE"
  echo "✅ Binds duplicados de config.yml removidos."
else
  echo "⚠️ docker-compose.yml não encontrado para limpar binds duplicados."
fi





# ---------------------------------------------------------------
# 4️⃣.1 Recriando binds corretos para o serviço 'registryctl' (Inserção Pontual)
# ---------------------------------------------------------------
echo "💉 Injetando bind do config.yml para 'registryctl'..."

# Remove qualquer injeção anterior (para idempotência)
sudo sed -i '/config\/registryctl\/config\.yml/d' "${COMPOSE_FILE}" || true
sudo sed -i '/^[[:space:]]*target: \/etc\/registryctl\/config\.yml/d' "${COMPOSE_FILE}" || true

# Encontra a linha 'volumes:' dentro do serviço 'registryctl' e injeta APENAS o config.yml
sudo awk '
  /^  registryctl:$/ {in_regctl=1}
  in_regctl && /^    volumes:$/ {
    print
    print "      - ./common/config/registryctl/config.yml:/etc/registryctl/config.yml:ro"
    in_regctl=0; next
  }
  {print}
' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_regctl"
sudo mv "${COMPOSE_FILE}.tmp_regctl" "${COMPOSE_FILE}"

echo "✅ Bloco 'registryctl.volumes' corrigido com sucesso."





# ---------------------------------------------------------------
# 🧩 LIMPEZA FINAL DE LINHAS 'target:' E 'source:' ÓRFÃS (registry)
# ---------------------------------------------------------------
echo "🧹 Limpando resíduos 'target:' e 'source:' órfãos do serviço 'registry'..."

COMPOSE_FILE="/opt/ngsoc-deploy/data/harbor/installer/harbor/docker-compose.yml"

# Remove linhas 'target:' ou 'source:' soltas (sem '-')
sudo sed -i '/^[[:space:]]*target:[[:space:]]/d' "${COMPOSE_FILE}"
sudo sed -i '/^[[:space:]]*source:[[:space:]]/d' "${COMPOSE_FILE}"

# Reinjeta binds corretos e seguros para o serviço registry
sudo awk '
  /^  registry:$/ {in_reg=1}
  in_reg && /^    volumes:$/ {
    print
    print "      - /opt/ngsoc-deploy/data/harbor/data/registry:/storage:z"
    print "      - ./common/config/registry/:/etc/registry/:z"
    print "      - /opt/ngsoc-deploy/data/harbor/data/secret/registry/root.crt:/etc/registry/root.crt:ro"
    print "      - /opt/ngsoc-deploy/data/harbor/installer/harbor/common/config/shared/trust-certificates:/harbor_cust_cert:ro"
    in_reg=0; next
  }
  {print}
' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_finalclean"
sudo mv "${COMPOSE_FILE}.tmp_finalclean" "${COMPOSE_FILE}"

echo "✅ Resíduos removidos e binds corretos reinjetados no serviço 'registry'."







# ---------------------------------------------------------------
# 🧩 FIX FINAL – Reconstrução completa do bloco 'portal.volumes'
# ---------------------------------------------------------------
echo "🧩 Reconstruindo bloco de volumes do serviço 'portal'..."

COMPOSE_FILE="/opt/ngsoc-deploy/data/harbor/installer/harbor/docker-compose.yml"

sudo awk '
  /^  portal:$/ {in_portal=1}
  in_portal && /^    volumes:$/ {
    print
    print "      - ./common/config/portal/nginx.conf:/etc/nginx/nginx.conf:ro"
    print "      - /opt/ngsoc-deploy/data/harbor/data/secret/cert:/etc/cert:z"
    print "      - /opt/ngsoc-deploy/data/harbor/data/portal:/var/lib/nginx/html:Z"
    in_portal=0; next
  }
  {print}
' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_portalvols"

sudo mv "${COMPOSE_FILE}.tmp_portalvols" "${COMPOSE_FILE}"
echo "✅ Bloco 'portal.volumes' reconstruído com sucesso."




# ---------------------------------------------------------------
# 🧩 FIX FINAL – Reconstrução completa do bloco 'proxy.volumes'
# ---------------------------------------------------------------
COMPOSE_FILE="/opt/ngsoc-deploy/data/harbor/installer/harbor/docker-compose.yml"
echo "🧩 Reconstruindo bloco de volumes do serviço 'proxy'..."

# 1️⃣ Remove quaisquer referências antigas e resíduos de volumes SSL/Nginx
sudo sed -i '/nginx\.conf:/d' "${COMPOSE_FILE}" || true
sudo sed -i '/ssl\/certs/d' "${COMPOSE_FILE}" || true
sudo sed -i '/ssl\/private/d' "${COMPOSE_FILE}" || true
sudo sed -i '/data\/nginx/d' "${COMPOSE_FILE}" || true

# 2️⃣ Reconstrói o bloco completo de volumes
sudo awk '
  /^  proxy:$/ {in_proxy=1}
  in_proxy && /^    volumes:$/ {
    print
    print "      - /etc/ssl/certs/nginx-selfsigned.crt:/etc/nginx/cert/server.crt:ro"
    print "      - /etc/ssl/private/nginx-selfsigned.key:/etc/nginx/cert/server.key:ro"
    print "      - ./common/config/nginx/nginx.conf:/etc/nginx/nginx.conf:ro"
    print "      - /opt/ngsoc-deploy/data/harbor/data/nginx:/var/log/nginx"
    in_proxy=0; next
  }
  {print}
' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_proxyvols"

sudo mv "${COMPOSE_FILE}.tmp_proxyvols" "${COMPOSE_FILE}"
echo "✅ Bloco 'proxy.volumes' reconstruído com sucesso."






# ---------------------------------------------------------------
# 🧩 FIX FINAL – Reconstrução completa do bloco 'registry.volumes'
# ---------------------------------------------------------------
echo "🧩 Reconstruindo bloco de volumes do serviço 'registry'..."

COMPOSE_FILE="/opt/ngsoc-deploy/data/harbor/installer/harbor/docker-compose.yml"

# 1️⃣ Remove linhas antigas potencialmente corrompidas
sudo sed -i '/registry\/config.yml/d' "${COMPOSE_FILE}" || true
sudo sed -i '/registry\/passwd/d' "${COMPOSE_FILE}" || true
sudo sed -i '/data\/registry/d' "${COMPOSE_FILE}" || true
sudo sed -i '/etc\/registry\/root.crt/d' "${COMPOSE_FILE}" || true
sudo sed -i '/harbor_cust_cert/d' "${COMPOSE_FILE}" || true

# 2️⃣ Reinjeção completa dos volumes corretos
sudo awk '
  /^  registry:$/ {in_registry=1}
  in_registry && /^    volumes:$/ {
    print
    print "      - ./common/config/registry/config.yml:/etc/registry/config.yml:ro"
    print "      - ./common/config/registry/passwd:/etc/registry/passwd:ro"
    print "      - /opt/ngsoc-deploy/data/harbor/data/registry:/storage:z"
    print "      - /opt/ngsoc-deploy/data/harbor/data/secret/registry/root.crt:/etc/registry/root.crt:ro"
    print "      - ./common/config/shared/trust-certificates:/harbor_cust_cert:ro"
    in_registry=0; next
  }
  {print}
' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_registryfix"

sudo mv "${COMPOSE_FILE}.tmp_registryfix" "${COMPOSE_FILE}"
echo "✅ Bloco 'registry.volumes' reconstruído com sucesso."




# ---------------------------------------------------------------
# 🧹 LIMPEZA FINAL – Remove traços vazios e binds quebrados no registry
# ---------------------------------------------------------------
echo "🧹 Limpando linhas vazias ou traços isolados do bloco 'registry.volumes'..."

COMPOSE_FILE="/opt/ngsoc-deploy/data/harbor/installer/harbor/docker-compose.yml"

sudo awk '
  BEGIN {in_reg=0}
  /^  registry:$/ {in_reg=1}
  in_reg && /^  [a-zA-Z0-9_-]+:$/ && $1 != "registry" {in_reg=0}
  {
    if (in_reg && $0 ~ /^ *- *$/) next
    print
  }
' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_cleanreg"

sudo mv "${COMPOSE_FILE}.tmp_cleanreg" "${COMPOSE_FILE}"
echo "✅ Linhas vazias e traços órfãos removidos do bloco registry."







# ---------------------------------------------------------------
# 💣 LIMPEZA FINAL DO BLOCO 'registry.volumes'
# ---------------------------------------------------------------
COMPOSE_FILE="/opt/ngsoc-deploy/data/harbor/installer/harbor/docker-compose.yml"
echo "💣 Limpando traços órfãos e volumes vazios do serviço 'registry' (final definitivo)..."

# Remove linhas que contenham apenas '-' (hífen solto)
sudo sed -i '/^[[:space:]]*-[[:space:]]*$/d' "${COMPOSE_FILE}" || true

# Remove entradas inválidas que começam com '-' mas não têm ':'
sudo sed -i '/^[[:space:]]*-[[:space:]]*[^:]*$/d' "${COMPOSE_FILE}" || true

# Remove linhas 'type: bind' órfãs
sudo sed -i '/^[[:space:]]*- type: bind$/d' "${COMPOSE_FILE}" || true

echo "✅ Bloco 'registry.volumes' limpo de resíduos e inválidos."







# ---------------------------------------------------------------
# ⚙️ FIX CAP_ADD/CAP_DROP DO SERVIÇO 'log' – Formato de array
# ---------------------------------------------------------------
COMPOSE_FILE="/opt/ngsoc-deploy/data/harbor/installer/harbor/docker-compose.yml"
echo "⚙️ Corrigindo formato de cap_add/cap_drop do serviço 'log'..."

sudo awk '
  BEGIN {in_log=0}
  /^  log:$/ {in_log=1; print; next}
  in_log && /^    cap_add:/ {
    print "    cap_add:"
    print "      - CHOWN"
    print "      - DAC_OVERRIDE"
    print "      - SETGID"
    print "      - SETUID"
    in_log=0; next
  }
  {print}
' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_caps"

sudo mv "${COMPOSE_FILE}.tmp_caps" "${COMPOSE_FILE}"
echo "✅ Bloco 'log.cap_add' normalizado para array YAML."





# ---------------------------------------------------------------
# ⚙️ FIX GLOBAL DE CAP_DROP/CAP_ADD – Formato de array em todos os serviços
# ---------------------------------------------------------------
COMPOSE_FILE="/opt/ngsoc-deploy/data/harbor/installer/harbor/docker-compose.yml"
echo "⚙️ Normalizando blocos cap_drop e cap_add para formato de array em todos os serviços..."

sudo awk '
  # Função que imprime bloco cap_drop/cap_add padrão
  function print_caps() {
    print "    cap_drop:"
    print "      - ALL"
    print "    cap_add:"
    print "      - CHOWN"
    print "      - DAC_OVERRIDE"
    print "      - SETGID"
    print "      - SETUID"
  }

  # Marca início de um serviço
  /^  [a-zA-Z0-9_-]+:$/ {in_service=1; print; next}

  # Detecta e substitui blocos cap_drop/cap_add
  in_service && /^    cap_drop:/ {
    print_caps()
    # pular linhas antigas de cap_drop/cap_add
    while (getline line) {
      if (line ~ /^    [a-zA-Z]/) { print line; break }
    }
    in_service=0
    next
  }

  {print}
' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_caps"

sudo mv "${COMPOSE_FILE}.tmp_caps" "${COMPOSE_FILE}"
echo "✅ Todos os serviços agora possuem cap_drop/cap_add em formato de lista YAML."






# ===============================================================
# 💣 TERAPIA DE CHOQUE: CAP_DROP / CAP_ADD LIMPOS E RECRIADOS
# ===============================================================
COMPOSE_FILE="/opt/ngsoc-deploy/data/harbor/installer/harbor/docker-compose.yml"
echo "💣 Terapia de choque: limpando e reinjetando blocos cap_drop/cap_add em todos os serviços..."

# 1️⃣ Remove qualquer definição antiga de cap_drop / cap_add
sudo sed -i '/^[[:space:]]*cap_drop:/d;/^[[:space:]]*cap_add:/d;/^[[:space:]]*-[[:space:]]*ALL$/d;/^[[:space:]]*-[[:space:]]*CHOWN$/d;/^[[:space:]]*-[[:space:]]*DAC_OVERRIDE$/d;/^[[:space:]]*-[[:space:]]*SETGID$/d;/^[[:space:]]*-[[:space:]]*SETUID$/d' "${COMPOSE_FILE}"

# 2️⃣ Reinsere blocos padronizados imediatamente após cada 'restart:' encontrado
sudo awk '
  /^    restart:/ {
    print
    print "    cap_drop:"
    print "      - ALL"
    print "    cap_add:"
    print "      - CHOWN"
    print "      - DAC_OVERRIDE"
    print "      - SETGID"
    print "      - SETUID"
    next
  }
  {print}
' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_caps"

sudo mv "${COMPOSE_FILE}.tmp_caps" "${COMPOSE_FILE}"
echo "✅ Blocos cap_drop/cap_add recriados de forma limpa e padronizada."



# ===============================================================
# 🧩 NORMALIZAÇÃO FINAL DE NETWORKS – Corrige services.proxy.networks
# ===============================================================
COMPOSE_FILE="/opt/ngsoc-deploy/data/harbor/installer/harbor/docker-compose.yml"
echo "🧩 Corrigindo formato de 'networks:' para lista YAML em todos os serviços..."

sudo awk '
  function fix_networks_block(line) {
    gsub(/^[ \t]+|[ \t]+$/, "", line)
    if (line ~ /^networks:/ && line !~ /-\s*\w+/) {
      print "    networks:"
      print "      - default"
      next_line=""
      return 1
    }
    return 0
  }

  /^  [a-zA-Z0-9_-]+:$/ { in_service=1; print; next }

  in_service && /^[ ]{4}networks:/ {
    if (fix_networks_block($0)) next
  }

  { print }
' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_netfix"

sudo mv "${COMPOSE_FILE}.tmp_netfix" "${COMPOSE_FILE}"
echo "✅ Formato de 'networks:' normalizado (todas as entradas são listas YAML)."




# ===============================================================
# 🧩 NORMALIZAÇÃO FINAL DE DEPENDS_ON – Corrige strings únicas
# ===============================================================
COMPOSE_FILE="/opt/ngsoc-deploy/data/harbor/installer/harbor/docker-compose.yml"
echo "🧩 Corrigindo formato de 'depends_on:' para lista YAML em todos os serviços..."

sudo awk '
  # Função para corrigir depends_on
  function fix_depends_on(line) {
    gsub(/^[ \t]+|[ \t]+$/, "", line)
    if (line ~ /^depends_on:/ && line !~ /-\s*\w+/) {
      split(line, parts, ":")
      dep = parts[2]
      gsub(/^[ \t]+/, "", dep)
      if (dep != "") {
        print "    depends_on:"
        print "      - " dep
      } else {
        print "    depends_on:"
        print "      - log"
      }
      return 1
    }
    return 0
  }

  /^  [a-zA-Z0-9_-]+:$/ { in_service=1; print; next }

  in_service && /^[ ]{4}depends_on:/ {
    if (fix_depends_on($0)) next
  }

  { print }
' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_depfix"

sudo mv "${COMPOSE_FILE}.tmp_depfix" "${COMPOSE_FILE}"
echo "✅ Formato de 'depends_on:' normalizado (todas as entradas são listas YAML)."




# ===============================================================
# 🧩 NORMALIZAÇÃO FINAL DE VOLUMES – Corrige strings e duplicatas
# ===============================================================
COMPOSE_FILE="/opt/ngsoc-deploy/data/harbor/installer/harbor/docker-compose.yml"
echo "🧩 Corrigindo formato de 'volumes:' para lista YAML em todos os serviços..."

sudo awk '
  function fix_volumes_block(line) {
    gsub(/^[ \t]+|[ \t]+$/, "", line)
    if (line ~ /^volumes:/ && line !~ /-\s*\S+/) {
      split(line, parts, ":")
      vol = parts[2]
      gsub(/^[ \t]+/, "", vol)
      print "    volumes:"
      if (vol != "") {
        print "      - " vol
      } else {
        print "      - /opt/ngsoc-deploy/logs/harbor:/var/log/harbor"
      }
      return 1
    }
    return 0
  }

  /^  [a-zA-Z0-9_-]+:$/ { in_service=1; print; next }

  in_service && /^[ ]{4}volumes:/ {
    if (fix_volumes_block($0)) next
  }

  { print }
' "${COMPOSE_FILE}" > "${COMPOSE_FILE}.tmp_volfix"

sudo mv "${COMPOSE_FILE}.tmp_volfix" "${COMPOSE_FILE}"
echo "✅ Formato de 'volumes:' normalizado (todas as entradas são listas YAML)."




# ---------------------------------------------------------------
# ✅ 		Validação final: docker compose config -q
# ---------------------------------------------------------------
echo "=============================================================="
echo "🧪 Validando YAML com 'docker compose config -q'..."
if docker compose -f "${COMPOSE_FILE}" config -q 2> "${COMPOSE_FILE}.lint.err"; then
  echo "✅ YAML válido."
else
  echo "❌ YAML inválido. Mostrando diagnóstico (primeiras 60 linhas):"
  nl -ba "${COMPOSE_FILE}.lint.err" | sed -n '1,60p' || true
  echo "🔎 Dica: execute 'nl -ba ${COMPOSE_FILE} | sed -n \"1,220p\"' e ajuste as linhas citadas."
  exit 1
fi

# ---------------------------------------------------------------
# 🔚 Conclusão
# ---------------------------------------------------------------
echo "=============================================================="
[[ -f "${INSTALLER_HARBOR_DIR}/docker-compose.yml" ]] \
  && echo "📄 docker-compose.yml gerado com sucesso em ${INSTALLER_HARBOR_DIR}/docker-compose.yml" \
  || echo "⚠️ docker-compose.yml não localizado; verifique ${GEN_DIR}"

printf "📁 Itens-chave:\n   - %s\n" \
  "${CERTS_DIR_COMPAT}/harbor.key" \
  "${CERTS_DIR_COMPAT}/harbor.crt" \
  "${SECRETKEY_FILE}" \
  "${TLS_DIR}/harbor_internal_ca.crt" \
  "${HARBOR_YML}"

echo "=============================================================="
echo "🎯 FIX-PREPARE FINAL UNIVERSAL — CONCLUÍDO."
echo "=============================================================="
