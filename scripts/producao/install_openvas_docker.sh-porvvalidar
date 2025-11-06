#!/usr/bin/env bash
set -euo pipefail

PLAYBOOK_FILE="/opt/ngsoc-deploy/Ansible/playbooks/deploy_openvas.yml"
NGSOC_DIR="/opt/ngsoc-deploy"
LOGFILE="/opt/ngsoc-deploy/logs/install_openvas.log"

GSA_HOST_PORT="${GSA_HOST_PORT:-9392}"
GSA_ADMIN_USER="${GSA_ADMIN_USER:-admin}"
GSA_ADMIN_PASS="${GSA_ADMIN_PASS:-Ng5ocAdm1n!23}"

mkdir -p "$(dirname "$LOGFILE")"
exec > >(tee -a "$LOGFILE") 2>&1

echo "=========================================================="
echo "🚀 INÍCIO DA INSTALAÇÃO DO OPENVAS/GVM (VIA ANSIBLE)"
echo "=========================================================="
date

# Pré-checks
if ! command -v ansible-playbook &>/dev/null; then
  echo "❌ ERRO: ansible-playbook não encontrado. Instale o Ansible antes de continuar."
  exit 1
fi

if ! command -v docker &>/dev/null; then
  echo "❌ ERRO: docker não encontrado. Instale/ habilite o Docker antes de continuar."
  exit 2
fi

if [ ! -f "${PLAYBOOK_FILE}" ]; then
  echo "❌ ERRO: Playbook não encontrado em ${PLAYBOOK_FILE}"
  exit 3
fi

echo "🔍 Verificando sintaxe do Playbook..."
if ! ansible-playbook --syntax-check "${PLAYBOOK_FILE}"; then
  echo "❌ ERRO: Sintaxe inválida no playbook. Corrija antes de prosseguir."
  exit 4
fi

echo "🔧 Executando playbook (ansible) - logs: ${LOGFILE}"
ansible-playbook "${PLAYBOOK_FILE}" \
  -i "localhost," \
  --connection=local \
  --extra-vars "gsa_host_port=${GSA_HOST_PORT} gsa_admin_user=${GSA_ADMIN_USER} gsa_admin_pass=${GSA_ADMIN_PASS}"

RC=$?
if [ $RC -ne 0 ]; then
  echo "❌ Falha durante execução do playbook (exit code ${RC}). Verifique ${LOGFILE}"
  exit $RC
fi

SERVER_IP=$(hostname -I | awk '{print $1}')
echo "=========================================================="
echo "✅ OPENVAS/GVM DEPLOY CONCLUÍDO COM SUCESSO!"
echo "=========================================================="
echo "🌐 Acesse: http://${SERVER_IP}:${GSA_HOST_PORT}/"
echo "👤 Usuário: ${GSA_ADMIN_USER}"
echo "🔒 Senha: ${GSA_ADMIN_PASS}"
echo "📄 Leia: ${NGSOC_DIR}/docs/openvas/README.txt"
echo "📌 Log da instalação: ${LOGFILE}"
echo "=========================================================="
