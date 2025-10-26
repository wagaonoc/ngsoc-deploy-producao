#!/usr/bin/env bash
# salvar como: /tmp/run_zap_evidence.sh
# chmod +x /tmp/run_zap_evidence.sh
# rodar: sudo /tmp/run_zap_evidence.sh

set -euo pipefail
OUT=/tmp/evidencia_zap.txt
CONTAINER="ngsoc_zap"
GATEWAY="$(sudo docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || echo '172.17.0.1')"
TARGET_IP="${GATEWAY:-172.17.0.1}"
TARGET_PORT=8085
ZAP_API="http://localhost:8080"
TMPDIR="/tmp/zap_evidence_$(date +%Y%m%d%H%M%S)"
mkdir -p "$TMPDIR"
echo "=== EVIDÊNCIA ZAP - $(date -u +"%Y-%m-%d %H:%M:%SZ") ===" > "$OUT"

echo -e "\n== 1) Verificar container existe ==" | tee -a "$OUT"
if ! sudo docker inspect "$CONTAINER" >/dev/null 2>&1; then
  echo "ERRO: container $CONTAINER nao encontrado" | tee -a "$OUT"
  exit 1
fi
sudo docker inspect --format 'Container: {{.Name}} (ID: {{.Id}}) - Image: {{.Config.Image}}' "$CONTAINER" | tee -a "$OUT"

echo -e "\n== 2) Ferramentas disponíveis dentro do container ==" | tee -a "$OUT"
sudo docker exec "$CONTAINER" sh -lc 'which wget 2>/dev/null || true; which curl 2>/dev/null || true; which nc 2>/dev/null || true; which python3 2>/dev/null || true' \
  | sed '/^$/d' | tee -a "$OUT"

echo -e "\n== 3) Teste de conectividade (do container para $TARGET_IP:$TARGET_PORT) ==" | tee -a "$OUT"
# Try wget with headers
sudo docker exec "$CONTAINER" sh -lc "if command -v wget >/dev/null 2>&1; then wget -S --timeout=5 -O - http://$TARGET_IP:$TARGET_PORT 2>&1 | head -n 50; fi" > "$TMPDIR/wget_out.txt" 2>&1 || true
# Try curl (fallback)
sudo docker exec "$CONTAINER" sh -lc "if command -v curl >/dev/null 2>&1; then curl -sS -I --max-time 5 http://$TARGET_IP:$TARGET_PORT 2>&1 || true; fi" > "$TMPDIR/curl_out.txt" 2>&1 || true
# Try nc (port check)
sudo docker exec "$CONTAINER" sh -lc "if command -v nc >/dev/null 2>&1; then nc -vz -w 3 $TARGET_IP $TARGET_PORT 2>&1 || true; fi" > "$TMPDIR/nc_out.txt" 2>&1 || true

echo "--- wget output (first 50 lines) ---" | tee -a "$OUT"
sed -n '1,50p' "$TMPDIR/wget_out.txt" | tee -a "$OUT"
echo "--- curl -I output ---" | tee -a "$OUT"
sed -n '1,50p' "$TMPDIR/curl_out.txt" | tee -a "$OUT"
echo "--- nc output ---" | tee -a "$OUT"
sed -n '1,50p' "$TMPDIR/nc_out.txt" | tee -a "$OUT"

echo -e "\n== 4) Chamar ZAP API: Spider e Active Scan ==" | tee -a "$OUT"
SPIDER_RESP=$(curl -s "$ZAP_API/JSON/spider/action/scan/?url=http://$TARGET_IP:$TARGET_PORT/" || true)
ASCAN_RESP=$(curl -s "$ZAP_API/JSON/ascan/action/scan/?url=http://$TARGET_IP:$TARGET_PORT/" || true)
echo "Spider response: $SPIDER_RESP" | tee -a "$OUT"
echo "Active scan response: $ASCAN_RESP" | tee -a "$OUT"

# extrair ids se existirem
SPIDER_ID=$(echo "$SPIDER_RESP" | jq -r '.scan // .scanId // empty' 2>/dev/null || true)
ASCAN_ID=$(echo "$ASCAN_RESP" | jq -r '.scan // .scanId // empty' 2>/dev/null || true)
echo "Spider ID: ${SPIDER_ID:-<none>}" | tee -a "$OUT"
echo "Active Scan ID: ${ASCAN_ID:-<none>}" | tee -a "$OUT"

echo -e "\n== 5) Monitorar progresso do active scan (tempo max 180s) ==" | tee -a "$OUT"
if [ -n "$ASCAN_ID" ]; then
  timeout=180
  interval=5
  elapsed=0
  while [ $elapsed -le $timeout ]; do
    status=$(curl -s "$ZAP_API/JSON/ascan/view/status/?scanId=$ASCAN_ID" | jq -r '.status // empty' 2>/dev/null || true)
    echo "$(date -u +"%Y-%m-%dT%H:%M:%SZ") status=$status (elapsed ${elapsed}s)" | tee -a "$OUT"
    if [ "$status" = "100" ] || [ -z "$status" ]; then
      break
    fi
    sleep $interval
    elapsed=$((elapsed+interval))
  done
else
  echo "No active scan id returned, skipping poll." | tee -a "$OUT"
fi

echo -e "\n== 6) Coletar logs do ZAP (ultimas 200 linhas) ==" | tee -a "$OUT"
sudo tail -n 200 /var/log/zap/zap.log 2>/dev/null | tee -a "$OUT" || echo "(arquivo /var/log/zap/zap.log não encontrado ou sem permissão)" | tee -a "$OUT"

echo -e "\n== 7) Buscar entradas específicas no Wazuh alerts (marca: 'VALIDAÇÃO COM SUCESSO DO ZAP') ==" | tee -a "$OUT"
# procura por marca exata, se existir
sudo grep -i "VALIDAÇÃO COM SUCESSO DO ZAP" /var/ossec/logs/alerts/alerts.json 2>/dev/null | tee -a "$OUT" || echo "nenhum alerta com a marca 'VALIDAÇÃO COM SUCESSO DO ZAP' encontrado" | tee -a "$OUT"

echo -e "\n== 8) Filtrar alerts.json por entradas recentes do zap (zap-rules) ==" | tee -a "$OUT"
sudo jq -r 'select(.decoder.name?"zap-audit":false) // select(.rule.groups? | index("zap-rules"))' /var/ossec/logs/alerts/alerts.json 2>/dev/null | tee -a "$OUT" || echo "Sem entradas filtradas." | tee -a "$OUT"

echo -e "\n== 9) Salvar cópias para auditoria ==" | tee -a "$OUT"
cp /var/log/zap/zap.log "$TMPDIR/" 2>/dev/null || true
cp /var/ossec/logs/alerts/alerts.json "$TMPDIR/" 2>/dev/null || true
sudo docker inspect "$CONTAINER" > "$TMPDIR/container_inspect.json" 2>/dev/null || true
echo "Arquivos copiados para $TMPDIR" | tee -a "$OUT"

echo -e "\n== FIM - Relatório gerado em $OUT ==" | tee -a "$OUT"
echo "Arquivos adicionais: $(ls -1 "$TMPDIR" 2>/dev/null | sed 's/^/  - /')" | tee -a "$OUT"
