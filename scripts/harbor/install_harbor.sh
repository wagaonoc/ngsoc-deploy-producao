#!/bin/bash
set -euo pipefail

# ===============================================================
# 🚀 INSTALL_HARBOR - EXECUÇÃO COMPLETA (SAFE + README)
# ===============================================================
# - Garante fix_prepare
# - Executa deploy via compose ou ansible
# - Gera documentação README com informações do ambiente
# - Faz verificação de saúde após execução
# ===============================================================

BASE_DIR="/opt/ngsoc-deploy"
SCRIPTS_DIR="${BASE_DIR}/scripts"
HARBOR_SCRIPTS_DIR="${SCRIPTS_DIR}/harbor"
HARBOR_DATA="${BASE_DIR}/data/harbor"
INSTALLER_DIR="${HARBOR_DATA}/installer/harbor"
LOG_DIR="${BASE_DIR}/logs/harbor"
DOCS_DIR="${BASE_DIR}/docs/harbor"
FIX_SCRIPT="${HARBOR_SCRIPTS_DIR}/fix_prepare.sh"
PLAYBOOK="${BASE_DIR}/ansible/playbooks/harbor/deploy_harbor.yml"
VERIFY_SCRIPT="${HARBOR_SCRIPTS_DIR}/verify_harbor.sh"
README_FILE="${DOCS_DIR}/README.txt"

VERSION="v2.14.0"
DATE_NOW=$(date +"%Y-%m-%d %H:%M:%S")

echo "=============================================================="
echo "🚀 INSTALL_HARBOR iniciado"
echo "=============================================================="

sudo mkdir -p "${HARBOR_DATA}" "${INSTALLER_DIR}" "${LOG_DIR}" "${DOCS_DIR}"

if [[ -x "${FIX_SCRIPT}" ]]; then
  sudo bash "${FIX_SCRIPT}"
else
  echo "❌ fix_prepare.sh não encontrado!"
  exit 1
fi

if [[ -f "${PLAYBOOK}" && $(command -v ansible) ]]; then
  echo "▶️ Executando playbook ${PLAYBOOK}"
  sudo ansible-playbook "${PLAYBOOK}" || exit 1
else
  echo "▶️ Subindo Harbor via Docker Compose..."
  pushd "${INSTALLER_DIR}" >/dev/null
  sudo docker compose up -d
  popd >/dev/null
fi

[[ -x "${VERIFY_SCRIPT}" ]] && sudo bash "${VERIFY_SCRIPT}"

# ---------------------------------------------------------------
# 📘 Gerar README.txt com todas as informações pós-instalação
# ---------------------------------------------------------------
echo "📝 Gerando documentação em ${README_FILE}..."
sudo tee "${README_FILE}" >/dev/null <<EOF
==========================================================
NG-SOC - Harbor Registry Usage & Access (${VERSION})
==========================================================

📅 Data da Instalação: ${DATE_NOW}
📂 Diretórios Importantes:
- Base: ${HARBOR_DATA}
- Installer: ${INSTALLER_DIR}
- Logs: ${LOG_DIR}
- Certificados: ${HARBOR_DATA}/certs
- Secrets: ${HARBOR_DATA}/data/secret
- Configurações: ${INSTALLER_DIR}/common/config

🌐 ACESSO AO PORTAL WEB:
- HTTPS: https://harbor.local:8443 (Recomendado)
- HTTP:  http://harbor.local:8081

🧭 MAPEAR NO HOSTS:
- Adicione em /etc/hosts: 192.168.100.23  harbor.local

🔒 CREDENCIAIS ADMINISTRATIVAS:
- Usuário: admin
- Senha: Harbor12345

🗄️ BANCO DE DADOS INTERNO (PostgreSQL):
- Host interno: harbor-db
- Porta: 5432
- Usuário: postgres
- Senha: HarborDBpass

🐳 SERVIÇOS HARBOR (Containers):
| Serviço (Compose) | Imagem | Função Primária |
| :--- | :--- | :--- |
| nginx | goharbor/nginx-photon | Proxy reverso e SSL |
| harbor-core | goharbor/harbor-core | API e autenticação |
| harbor-portal | goharbor/harbor-portal | Interface Web |
| registry | goharbor/registry-photon | Armazenamento de imagens |
| registryctl | goharbor/harbor-registryctl | Controlador do Registry |
| harbor-db | goharbor/harbor-db | Banco de dados PostgreSQL |
| redis | goharbor/redis-photon | Cache e sessões |
| harbor-jobservice | goharbor/harbor-jobservice | Tarefas e replicações |
| trivy-adapter | goharbor/trivy-adapter-photon | Scanner de vulnerabilidades |
| harbor-log | goharbor/harbor-log | Coleta central de logs |

🔧 COMANDOS BÁSICOS:
- Status: cd ${INSTALLER_DIR} && docker compose ps
- Logs (exemplo): docker logs -f harbor-core
- Parar: cd ${INSTALLER_DIR} && docker compose down
- Restart: cd ${INSTALLER_DIR} && docker compose up -d

⚠️ NOTAS CRÍTICAS DE SEGURANÇA:
1. Porta 1514 (Syslog) desativada no Harbor para evitar conflito com Wazuh.
   Logs são coletados via arquivo em: ${LOG_DIR}
2. Certificado SSL autoassinado em uso:
   - nginx-selfsigned.crt / nginx-selfsigned.key
3. O cliente Docker precisa confiar no certificado para push/pull.
4. Host 'harbor.local' deve resolver corretamente o IP do servidor.

📞 SUPORTE E MANUTENÇÃO:
- Time SOC Positivo+ (ngsoc@positivo.com)
- Manual técnico: /opt/ngsoc-deploy/docs/harbor/
==========================================================
EOF

echo "=============================================================="
echo "✅ INSTALL_HARBOR concluído com sucesso!"
echo "📘 Documentação disponível em: ${README_FILE}"
echo "=============================================================="
