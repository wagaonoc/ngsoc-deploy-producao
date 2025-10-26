#!/bin/bash
set -e
echo "=========================================================="
echo "🚀 INÍCIO: Instalação/Provisionamento do Harbor (Ansible)"
echo "=========================================================="

INSTALL_DIR="/opt/ngsoc-deploy/data/harbor/installer"
CONFIG_DIR="${INSTALL_DIR}/common/config/jobservice"

# 1. Limpeza de containers antigos
echo "🧹 Limpando containers antigos do Harbor..."
docker compose -f "${INSTALL_DIR}/docker-compose.yml" down || true

# 2. Garantir estrutura de diretórios
echo "📁 Garantindo diretórios necessários..."
mkdir -p \
  /opt/ngsoc-deploy/logs/harbor \
  /opt/ngsoc-deploy/data/harbor/data/job_logs \
  "${CONFIG_DIR}"

# 3. Corrigir permissões
echo "🔐 Ajustando permissões..."
chmod -R 755 /opt/ngsoc-deploy/data/harbor
chmod -R 755 /opt/ngsoc-deploy/logs/harbor
chmod 644 "${CONFIG_DIR}/config.yml" 2>/dev/null || true
chown -R root:root /opt/ngsoc-deploy/data/harbor

# 4. Gerar arquivo de configuração do Jobservice corrigido
echo "🧩 Aplicando configuração corrigida do jobservice..."
tee "${CONFIG_DIR}/config.yml" > /dev/null <<'EOF'
---
protocol: "http"
port: 8080

worker_pool:
  workers: 10
  backend: "redis"
  redis_pool:
    redis_url: redis://redis:6379/2?idle_timeout_seconds=30
    namespace: "harbor_job_service_namespace"
    idle_timeout_second: 3600

job_loggers:
  - name: "STD_OUTPUT"
    level: "INFO"
  - name: "FILE"
    level: "INFO"
    settings:
      base_dir: "/var/log/jobs"
      filename: "jobservice.log"

loggers:
  - name: "STD_OUTPUT"
    level: "INFO"
  - name: "FILE"
    level: "INFO"
    settings:
      base_dir: "/var/log/jobs"
      filename: "jobservice.log"

reaper:
  max_update_hours: 24
  max_dangling_hours: 168

max_retrieve_size_mb: 10
EOF

# 5. Aplicar permissões novamente
chmod 644 "${CONFIG_DIR}/config.yml"
chown root:root "${CONFIG_DIR}/config.yml"

# 6. Deploy via Ansible ou Compose
echo "🚀 Implantando containers Harbor..."
docker compose -f "${INSTALL_DIR}/docker-compose.yml" up -d

echo "✅ Instalação concluída com sucesso!"
