#!/bin/bash
set -e

PLAYBOOK_FILE="/opt/ngsoc-deploy/Ansible/playbooks/deploy_trivy.yml"
LOG_DIR="/opt/ngsoc-deploy/logs/trivy"
README_FILE="/opt/ngsoc-deploy/docs/trivy/README.txt"
CONTAINER_NAME="ngsoc_trivy"
SERVER_PORT=4954

echo "=========================================================="
echo "🚀 INÍCIO: Instalação/Provisionamento do Trivy (Ansible)"
echo "=========================================================="

# ==========================================================
# 🔧 Correção definitiva de logs para Rsyslog + Wazuh
# ==========================================================
echo "🧩 Aplicando correções de diretórios de log..."
sudo mkdir -p /var/log/trivy
sudo chown -R syslog:adm /var/log/trivy
sudo chmod -R 750 /var/log/trivy
sudo systemctl restart rsyslog
echo "✅ Diretório /var/log/trivy ajustado para syslog/wazuh."

# Garantir diretórios locais do projeto
mkdir -p "$LOG_DIR"
mkdir -p "$(dirname "$README_FILE")"

echo "🔍 Verificando sintaxe do Playbook..."
if ! ansible-playbook "$PLAYBOOK_FILE" --syntax-check; then
    echo "❌ ERRO: Sintaxe do Playbook inválida."
    exit 1
fi
echo "✅ Sintaxe do Playbook OK."

# Executar o playbook
echo "⚙️  Executando Playbook para implantação do Trivy..."
if ansible-playbook "$PLAYBOOK_FILE"; then
    echo "=========================================================="
    echo "✅ TRIVY: Playbook executado com sucesso!"
    echo "=========================================================="
    echo "📁 Logs persistentes: $LOG_DIR"
    echo "📘 Documentação: $README_FILE"
    echo ""
    echo "🔎 Verificando status do container..."
    docker ps --filter "name=$CONTAINER_NAME"
    echo ""
    echo "=========================================================="
    echo "📌 TESTES RÁPIDOS:"
    echo "----------------------------------------------------------"
    echo "🩺 Testar status da API:"
    echo "   curl -s http://localhost:$SERVER_PORT/health | jq ."
    echo ""
    echo "🐳 Testar scan via cliente (RPC):"
    echo "   docker exec -it $CONTAINER_NAME sh -c \"TRIVY_SERVER='http://localhost:$SERVER_PORT' trivy image alpine:latest\""
    echo ""
    echo "📜 Ver logs em tempo real:"
    echo "   sudo tail -f $LOG_DIR/trivy-server.log"
    echo "=========================================================="
else
    echo "❌ ERRO: Falha na execução do Playbook."
    exit 1
fi
