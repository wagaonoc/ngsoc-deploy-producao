#!/usr/bin/env bash
# install_metasploit.sh - wrapper (Ansible)
set -euo pipefail

ANSIBLE_PLAYBOOK="/opt/ngsoc-deploy/Ansible/playbooks/deploy_metasploit.yml"
MSF_DOCS_PATH="/opt/ngsoc-deploy/docs/metasploit"
MSF_CREDS_FILE="${MSF_DOCS_PATH}/credentials.txt"

# Vars (podem ser exportadas ou passadas via --extra-vars)
MSF_DB_USER="${MSF_DB_USER:-msfuser}"
MSF_DB_NAME="${MSF_DB_NAME:-msfdb}"
MSF_DB_PASSWORD="${MSF_DB_PASSWORD:-}"

# Argumentos CLI (para --force-reinit)
MSF_FORCE_REINIT="${MSF_FORCE_REINIT:-false}"
while [ $# -gt 0 ]; do
  case "$1" in
    --force-reinit)
      MSF_FORCE_REINIT="true"
      shift
      ;;
    *)
      echo "⚠️ Unknown arg: $1"
      shift
      ;;
  esac
done

# generate password if not provided
if [ -z "$MSF_DB_PASSWORD" ]; then
  echo "[*] MSF DB password not provided — generating a strong random password..."
  MSF_DB_PASSWORD="$(openssl rand -base64 48 | tr -dc 'A-Za-z0-9@%_+=!#-' | head -c 32)"
fi
export MSF_DB_PASSWORD  # garante que playbook leia via lookup('env', ...)

echo "=========================================================="
echo "🚀 INÍCIO: Instalação/Provisionamento do Metasploit (Ansible)"
echo "=========================================================="
echo "Note: msf_force_reinit=${MSF_FORCE_REINIT}"

echo "🔍 Verificando sintaxe do Playbook..."
ansible-playbook --syntax-check "$ANSIBLE_PLAYBOOK"

echo "🔐 Executando playbook (passando senha e vars)..."
ansible-playbook "$ANSIBLE_PLAYBOOK" \
  --extra-vars "msf_db_password=${MSF_DB_PASSWORD} msf_db_user=${MSF_DB_USER} msf_db_name=${MSF_DB_NAME} msf_force_reinit=${MSF_FORCE_REINIT}"

echo "🔍 Verificando o status dos containers do Metasploit..."
docker ps | grep -E 'msf-db|metasploit' || echo "⚠️ Containers não encontrados"

# Garantir permissões do arquivo de credenciais
if [ -f "${MSF_CREDS_FILE}" ]; then
  chmod 600 "${MSF_CREDS_FILE}"
else
  echo "⚠️ Arquivo de credenciais não encontrado em ${MSF_CREDS_FILE}"
fi

echo "=========================================================="
echo "✅ METASPLOIT DEPLOYMENT WRAPPER FINALIZADO"
echo "=========================================================="
echo "  - README com comandos de acesso: ${MSF_DOCS_PATH}/README.txt"
echo "  - Credenciais (apenas root): ${MSF_CREDS_FILE}"
echo "  - Para forçar limpeza total do Postgres (DESTRUTIVO):"
echo "      ./install_metasploit.sh --force-reinit"
echo "=========================================================="
