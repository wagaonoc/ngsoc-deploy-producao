#!/bin/bash
set -euo pipefail

BASE="/opt/ngsoc-deploy"

echo "=================================================="
echo "   🏗️  PREPARANDO INFRAESTRUTURA COMPLETA DO NGSOC"
echo "=================================================="


###############################################
# 0. Criação explícita da base NGSOC
###############################################
echo "📌 Criando base: $BASE e $BASE/apps"

mkdir -p "$BASE"
mkdir -p "$BASE/apps"

chmod 755 "$BASE" "$BASE/apps"


###############################################
# 1. Diretórios raiz do NGSOC
###############################################
for dir in \
    "$BASE/data" \
    "$BASE/logs" \
    "$BASE/docs" \
    "$BASE/exports" \
    "$BASE/reports" \
    "$BASE/backups" \
    "$BASE/temp"
do
    mkdir -p "$dir"
    chmod 755 "$dir"
done

echo "📁 Diretórios raiz criados."


###############################################
# 2. Lista oficial de ferramentas
###############################################
TOOLS=(
    harbor
    metasploit
    mitmproxy
    nginx
    nginx-exports
    openvas
    zap
    trivy
    trivy-proxy
)


###############################################
# 3. Estrutura completa por ferramenta
###############################################
for tool in "${TOOLS[@]}"; do
    echo "🔧 Criando estrutura para: $tool"

    # /apps/<tool>
    for sub in build config deploy docker docs installer; do
        mkdir -p "$BASE/apps/$tool/$sub"
        chmod 755 "$BASE/apps/$tool/$sub"
    done

    # /data/<tool>
    mkdir -p "$BASE/data/$tool"
    chmod 755 "$BASE/data/$tool"

    # /logs/<tool>
    mkdir -p "$BASE/logs/$tool"
    chmod 755 "$BASE/logs/$tool"

    # /docs/<tool>
    mkdir -p "$BASE/docs/$tool"
    chmod 755 "$BASE/docs/$tool"

    # /exports/<tool>
    mkdir -p "$BASE/exports/$tool"
    chmod 755 "$BASE/exports/$tool"

    # /reports/<tool>
    mkdir -p "$BASE/reports/$tool"
    chmod 755 "$BASE/reports/$tool"
done

echo "📁 Estrutura completa por ferramenta criada."


###############################################
# 4. Subpastas internas específicas do Harbor
###############################################
echo "🔧 Criando subdiretórios internos do Harbor..."

HARBOR_DATA="$BASE/data/harbor/data"

for d in ca_download database job_logs redis registry secret trivy-adapter; do
    mkdir -p "$HARBOR_DATA/$d"
    chmod 755 "$HARBOR_DATA/$d"
done

echo "📁 Estrutura interna do Harbor criada."


###############################################
# 5. Aviso sobre certificados
###############################################
if [[ ! -f /etc/ssl/certs/nginx-selfsigned.crt ]]; then
    echo "⚠️  Certificado SSL não encontrado."
    echo "    → Gere ou copie antes da instalação."
fi


echo "=================================================="
echo "   ✅ INFRAESTRUTURA COMPLETA DO NGSOC PRONTA"
echo "=================================================="
