#!/usr/bin/env bash
set -euo pipefail

PLAYBOOK="/opt/ngsoc-deploy/Ansible/playbooks/deploy_mitmproxy.yml"

echo "=========================================================="
echo "🚀 INÍCIO: Instalando MITMProxy container (ngsoc_mitmproxy)"
echo "=========================================================="

if ! command -v ansible-playbook &>/dev/null; then
  echo "❌ Erro: ansible-playbook não encontrado. Instale o Ansible antes."
  exit 2
fi

if [ ! -f "$PLAYBOOK" ]; then
  echo "❌ Erro: Playbook não encontrado em $PLAYBOOK"
  exit 3
fi

echo "Executando playbook: $PLAYBOOK"
ansible-playbook "$PLAYBOOK"
RC=$?

if [ $RC -eq 0 ]; then
  echo
  echo "✅ MITMProxy implantado (ou atualizado) com sucesso."
  echo "Acesse UI: http://$(hostname -I | awk '{print $1}'):8090/#/flows"
  echo "Se quiser baixar o CA (após nginx estar ativo):"
  echo "  http://$(hostname -I | awk '{print $1}'):8085/mitmproxy-ca-cert.pem"
  exit 0
else
  echo "❌ Falha ao executar playbook (exit code $RC). Verifique logs do Ansible."
  exit $RC
fi
