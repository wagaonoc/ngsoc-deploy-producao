#!/bin/bash
set -euo pipefail

PLAYBOOK_FILE="/opt/ngsoc-deploy/Ansible/playbooks/deploy_zap.yml"
TOOL_NAME="OWASP ZAP"

echo "=========================================================="
echo "🚀 INÍCIO DA INSTALAÇÃO DE $TOOL_NAME (VIA ANSIBLE)"
echo "=========================================================="

if ! command -v ansible-playbook &> /dev/null; then
    echo "❌ ERRO: ansible-playbook não encontrado. Instale o Ansible."
    exit 1
fi

if [ ! -f "$PLAYBOOK_FILE" ]; then
    echo "❌ ERRO: Playbook não encontrado em $PLAYBOOK_FILE"
    exit 2
fi

# Garantir diretório docs (para o README gerado)
sudo mkdir -p /opt/ngsoc-deploy/docs/zap
sudo chown root:root /opt/ngsoc-deploy/docs/zap
sudo chmod 0755 /opt/ngsoc-deploy/docs/zap

# Executa o playbook (com saída legível)
if ansible-playbook "$PLAYBOOK_FILE"; then
    echo "✅ EXECUÇÃO CONCLUÍDA. Verifique /opt/ngsoc-deploy/docs/zap/README.txt para instruções."
    exit 0
else
    echo "❌ ERRO: O playbook falhou. Verifique logs do Ansible."
    exit 3
fi
