#!/bin/bash
echo "==================================================="
echo "🔄 Reiniciando todos os contêineres Docker instalados..."
echo "==================================================="
# Lista de diretórios de compose (usa a nova estrutura /data/)
# ALTERADO: Substituído 'owasp-zap' por 'mitmproxy'
COMPOSE_DIRS="/opt/ngsoc-deploy/data/gvm /opt/ngsoc-deploy/data/mitmproxy /opt/ngsoc-deploy/data/trivy /opt/ngsoc-deploy/data/mongodb"

RESTARTED_COUNT=0
for DIR in $COMPOSE_DIRS; do
    if [ -f "$DIR/docker-compose.yml" ]; then
        echo "Reiniciando serviços em $DIR..."
        sudo docker compose -f "$DIR/docker-compose.yml" restart || echo "⚠️ Falha ao reiniciar em $DIR. Serviço pode não estar ativo."
        RESTARTED_COUNT=$((RESTARTED_COUNT + 1))
    fi
done

if [ $RESTARTED_COUNT -eq 0 ]; then
    echo "⚠️ Nenhum arquivo docker-compose.yml encontrado. Nenhuma reinicialização necessária."
else
    echo "✅ Reinício concluído."
fi
