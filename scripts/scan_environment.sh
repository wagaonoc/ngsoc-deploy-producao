#!/bin/bash
# Script: scan_environment.sh
# Propósito: Varredura completa do ambiente Docker e GVM/OpenVAS em execução
# Gera relatório para reconstrução do deploy

# Configurações
REPORT_DIR="/opt/ngsoc-deploy/reports/scan_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$REPORT_DIR"

echo "=============================="
echo "Iniciando varredura do ambiente"
echo "Relatório será salvo em: $REPORT_DIR"
echo "=============================="

# 1. Informações do sistema
echo "[1/8] Coletando informações do sistema..."
uname -a > "$REPORT_DIR/system-info.txt"
echo "Hostname: $(hostname)" >> "$REPORT_DIR/system-info.txt"
echo "Memória:" >> "$REPORT_DIR/system-info.txt"
free -h >> "$REPORT_DIR/system-info.txt"
echo "Discos:" >> "$REPORT_DIR/system-info.txt"
df -h >> "$REPORT_DIR/system-info.txt"
echo "CPU:" >> "$REPORT_DIR/system-info.txt"
lscpu >> "$REPORT_DIR/system-info.txt"

# 2. Docker containers
echo "[2/8] Listando containers Docker..."
docker ps -a > "$REPORT_DIR/docker-ps.txt"

# 3. Docker imagens
echo "[3/8] Listando imagens Docker..."
docker images > "$REPORT_DIR/docker-images.txt"

# 4. Docker volumes
echo "[4/8] Listando volumes Docker..."
docker volume ls > "$REPORT_DIR/docker-volumes.txt"

# 5. Inspecionar containers individualmente
echo "[5/8] Inspecionando containers..."
for c in $(docker ps -aq); do
    cname=$(docker inspect --format '{{.Name}}' $c | sed 's|/||')
    echo "Inspecionando container: $cname"
    docker inspect $c > "$REPORT_DIR/docker-inspect-$cname.json"
done

# 6. Logs dos containers (últimos 200 linhas)
echo "[6/8] Coletando logs dos containers..."
for c in $(docker ps -aq); do
    cname=$(docker inspect --format '{{.Name}}' $c | sed 's|/||')
    docker logs --tail 200 $c > "$REPORT_DIR/docker-logs-$cname.txt" 2>&1
done

# 7. Variáveis de ambiente dos containers
echo "[7/8] Coletando variáveis de ambiente..."
for c in $(docker ps -aq); do
    cname=$(docker inspect --format '{{.Name}}' $c | sed 's|/||')
    docker inspect --format '{{json .Config.Env}}' $c > "$REPORT_DIR/docker-env-$cname.json"
done

# 8. Conectividade de portas dos serviços
echo "[8/8] Testando portas abertas dos serviços principais..."
PORTS=(9392 8089 8090)  # OpenVAS, Mitmproxy etc
for p in "${PORTS[@]}"; do
    nc -zv 127.0.0.1 $p &> "$REPORT_DIR/port-test-$p.txt" || echo "Porta $p fechada" >> "$REPORT_DIR/port-test-$p.txt"
done

echo "=============================="
echo "Varredura completa!"
echo "Todos os relatórios salvos em: $REPORT_DIR"
echo "=============================="
