#!/bin/bash
PLAYBOOK_FILE="/opt/ngsoc-deploy/Ansible/playbooks/deploy_wazuh.yml" # <-- CAMINHO CORRIGIDO
echo "=========================================================="
echo "🚀 INÍCIO DA INSTALAÇÃO DE Wazuh Manager (VIA ANSIBLE)"
echo "=========================================================="
if ! command -v ansible-playbook &> /dev/null; then
    echo "❌ ERRO CRÍTICO: Ansible não encontrado. Instale o Ansible (Opção 3)."
    exit 1
fi
if sudo ansible-playbook "$PLAYBOOK_FILE"; then
    echo "✅ EXECUÇÃO CONCLUÍDA. Verifique o status detalhado."
else
    echo "❌ ERRO: O Playbook Ansible falhou. Verifique o log."
    exit 1
fi

