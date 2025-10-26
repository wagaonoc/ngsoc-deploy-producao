#!/usr/bin/env bash
set -euo pipefail

PLAYBOOK="/opt/ngsoc-deploy/Ansible/playbooks/deploy_nginx_exports.yml"
DEFAULT_PORT="8085"

echo "=========================================================="
echo "🚀 INÍCIO: Instalando Nginx export container (ngsoc_exports)"
echo "=========================================================="

if ! command -v ansible-playbook &>/dev/null; then
  echo "❌ Erro: ansible-playbook não encontrado. Instale o Ansible antes."
  exit 2
fi

if [ ! -f "$PLAYBOOK" ]; then
  echo "❌ Erro: Playbook não encontrado em $PLAYBOOK"
  exit 3
fi

# tenta extrair a porta do playbook
PORT="$(sed -n 's/^[[:space:]]*export_port[[:space:]]*:[[:space:]]*\([0-9]\+\).*/\1/p' "$PLAYBOOK" | head -n1 || true)"
if [ -z "$PORT" ]; then
  PORT="$DEFAULT_PORT"
fi

HOST_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
HOST_IP="${HOST_IP:-127.0.0.1}"

echo "Playbook: $PLAYBOOK"
echo "Porta export detectada: $PORT"
echo "IP do host detectado: $HOST_IP"
echo

ansible-playbook "$PLAYBOOK"
RC=$?

if [ $RC -eq 0 ]; then
  echo
  echo "✅ Nginx export container implantado (ou atualizado) com sucesso."
  echo "Diretório export criado (se inexistente) e marker gravado."
  echo "Exemplo de link público (arquivo ainda não copiado):"
  echo "  http://${HOST_IP}:${PORT}/mitmproxy-ca-cert.pem"
  exit 0
else
  echo "❌ Falha ao executar playbook (exit code $RC). Verifique logs do Ansible."
  exit $RC
fi
