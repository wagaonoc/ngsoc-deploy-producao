#!/bin/bash
set -euo pipefail

BASE_DIR="/opt/ngsoc-deploy"
INSTALLER_DIR="${BASE_DIR}/data/harbor/installer/harbor"
LOG_DIR="${BASE_DIR}/logs/harbor"
HARBOR_URL="${HARBOR_URL:-https://localhost:8443}"
HARBOR_ADMIN_USER="${HARBOR_ADMIN_USER:-admin}"
HARBOR_ADMIN_PASS="${HARBOR_ADMIN_PASS:-Harbor12345}"

echo "=============================================================="
echo "🔍 VERIFY_HARBOR: status e checks básicos"
echo " Installer: ${INSTALLER_DIR}"
echo " Logs: ${LOG_DIR}"
echo " URL: ${HARBOR_URL}"
echo "=============================================================="

echo "1) Containers Harbor (filtro 'harbor' ou names conhecidos):"
sudo docker ps --format "table {{.Names}}\t{{.Status}}" | grep -Ei "harbor|registry|nginx|core|portal|jobservice" || true

echo "2) Últimos logs (tail 200) do diretório de logs do host:"
if [[ -d "${LOG_DIR}" ]]; then
  ls -1 "${LOG_DIR}"/* 2>/dev/null || true
  # show recent files if exist
  for f in "${LOG_DIR}"/* 2>/dev/null; do
    echo "---- tail ${f} ----"
    sudo tail -n 50 "${f}" || true
  done
else
  echo "⚠️ Diretório de logs não existe: ${LOG_DIR}"
fi

echo "3) Teste HTTPS e API (curl)"
# ignore cert validation for self-signed
if curl -sk --max-time 10 "${HARBOR_URL}" >/dev/null 2>&1; then
  echo "✅ HTTPS OK: ${HARBOR_URL}"
else
  echo "⚠️ Falha HTTPS: ${HARBOR_URL}"
fi

echo "4) Teste simples de API (listar projects)"
if curl -sk -u "${HARBOR_ADMIN_USER}:${HARBOR_ADMIN_PASS}" "${HARBOR_URL}/api/v2.0/projects" | grep -q '\['; then
  echo "✅ API responde (projects list)."
else
  echo "⚠️ API pode não estar pronta. Verifique logs e se credenciais estão corretas."
fi

echo "=============================================================="
echo "✅ VERIFY_HARBOR concluído."
echo "=============================================================="
