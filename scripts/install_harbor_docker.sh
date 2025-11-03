#!/bin/bash
# install_harbor.sh - wrapper Ansible + checagens
set -euo pipefail

ANSIBLE_PLAYBOOK="/opt/ngsoc-deploy/Ansible/playbooks/deploy_harbor.yml"
HARBOR_COMPOSE_DIR="/opt/ngsoc-deploy/data/harbor/installer"
HARBOR_DOCS_PATH="/opt/ngsoc-deploy/docs/harbor/README.txt"

HARBOR_HOSTNAME="harbor.local"
HARBOR_HTTPS_PORT="8443"
HARBOR_ADMIN_USER="admin"
HARBOR_ADMIN_PASS="Harbor12345"

echo "=========================================================="
echo "🚀 Instalação/Deploy do Harbor (Ansible)"
echo "=========================================================="

echo "🔍 Validando sintaxe do Playbook..."
ansible-playbook --syntax-check "$ANSIBLE_PLAYBOOK"

echo "🚀 Executando Playbook..."
set +e
ansible-playbook "$ANSIBLE_PLAYBOOK"
rc=$?
set -e

if [ $rc -ne 0 ]; then
  echo "⚠️ AVISO: ansible-playbook retornou código $rc. Conferindo estado..."
fi

echo "🔎 Verificando containers críticos (core/nginx)..."
cd "$HARBOR_COMPOSE_DIR"
UP_CRITICAL=$(docker compose ps -a | grep -E '(harbor-core|core|harbor-proxy|nginx)' | grep -i ' Up ' | wc -l)

if [ "$UP_CRITICAL" -lt 2 ]; then
  echo "=========================================================="
  echo "🚨 FALHA: Harbor não subiu corretamente."
  docker compose ps
  echo "=========================================================="
  exit 1
fi

echo "=========================================================="
echo "✅ Harbor operacional!"
echo "🌐 https://${HARBOR_HOSTNAME}:${HARBOR_HTTPS_PORT}"
echo "👤 ${HARBOR_ADMIN_USER} / ${HARBOR_ADMIN_PASS}"
echo "📄 ${HARBOR_DOCS_PATH}"
echo "=========================================================="
