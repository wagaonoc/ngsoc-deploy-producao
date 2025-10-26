#!/usr/bin/env bash
# test_metasploit_flow.sh
# Teste automatizado: Metasploit log -> host -> rsyslog -> wazuh
# Salve em /opt ou onde preferir e execute: sudo ./test_metasploit_flow.sh
set -euo pipefail
IFS=$'\n\t'

### ------- CONFIGURAÇÃO (edite se necessário) -------
METASP_CONTAINER="${METASP_CONTAINER:-metasploit}"
HOST_MOUNT_LOG_DIR="${HOST_MOUNT_LOG_DIR:-/opt/ngsoc-deploy/logs/metasploit}"
HOST_ORIG_FILE="${HOST_ORIG_FILE:-${HOST_MOUNT_LOG_DIR}/console_audit.log}"
RSYSLOG_DEST_DIR="${RSYSLOG_DEST_DIR:-/var/log/metasploit}"
RSYSLOG_DEST_FILE="${RSYSLOG_DEST_FILE:-${RSYSLOG_DEST_DIR}/framework.log}"
WAZUH_ALERTS_JSON="/var/ossec/logs/alerts/alerts.json"
WAZUH_OSSEC_LOG="/var/ossec/logs/ossec.log"
WAZUH_LOGTEST="/var/ossec/bin/wazuh-logtest"
WAIT_RSYSLOG_AFTER_RESTART=3
WAIT_WAZUH_AFTER_RESTART=6
# Timeout settings for waiting loops (seconds)
TIMEOUT_SHORT=15
TIMEOUT_MED=30
TIMEOUT_LONG=90
### ---------------------------------------------------

echo "=== Metasploit -> rsyslog -> Wazuh end-to-end test ==="
date

# Ensure required binaries
for cmd in docker sudo setfacl pgrep rsyslogd awk tail grep sed jq; do
  if ! command -v "${cmd}" >/dev/null 2>&1; then
    echo "AVISO: comando '${cmd}' não encontrado no PATH. Alguns checks poderão falhar."
  fi
done

# 0) Sanity: paths and container existence
echo
echo ">>> Checando container e caminhos..."
if ! docker ps --format '{{.Names}}' | grep -xq "${METASP_CONTAINER}"; then
  echo "ERRO: container '${METASP_CONTAINER}' não está em execução ou nome está errado."
  echo "Liste containers com: docker ps"
  exit 1
fi

mkdir -p "${HOST_MOUNT_LOG_DIR}"
sudo touch "${HOST_ORIG_FILE}"
sudo chown root:root "${HOST_ORIG_FILE}" || true

echo "OK: container '${METASP_CONTAINER}' rodando; arquivo host de origem: ${HOST_ORIG_FILE}"
echo

# 1) Detectar UID/GID do processo rsyslogd (para permissões ACL)
RSYS_PID=$(pgrep rsyslogd | head -n1 || true)
if [ -z "${RSYS_PID}" ]; then
  echo "ERRO: rsyslogd não encontrado em execução."
  exit 1
fi
RSYS_USER=$(ps -p "${RSYS_PID}" -o user= | awk '{print $1}')
RSYS_UID=$(ps -p "${RSYS_PID}" -o uid= | awk '{print $1}')
RSYS_GROUP=$(ps -p "${RSYS_PID}" -o group= | awk '{print $1}')
RSYS_GID=$(ps -p "${RSYS_PID}" -o gid= | awk '{print $1}')

echo "rsyslog PID=${RSYS_PID} user=${RSYS_USER} (UID=${RSYS_UID}) group=${RSYS_GROUP} (GID=${RSYS_GID})"

# 2) Garantir permissões de leitura/travessia para rsyslog e wazuh no diretório bind-mounted
echo
echo ">>> Ajustando ACLs para permitir leitura pelo rsyslog (UID ${RSYS_UID}) e usuario 'wazuh'..."
if command -v setfacl >/dev/null 2>&1; then
  sudo setfacl -m u:${RSYS_UID}:rx "${HOST_MOUNT_LOG_DIR}" || true
  sudo setfacl -m u:${RSYS_UID}:r "${HOST_MOUNT_LOG_DIR}"/*.log 2>/dev/null || true
  # também garanta leitura para wazuh (usuario)
  if id wazuh >/dev/null 2>&1; then
    sudo setfacl -m u:wazuh:rx "${HOST_MOUNT_LOG_DIR}" || true
    sudo setfacl -m u:wazuh:r "${HOST_MOUNT_LOG_DIR}"/*.log 2>/dev/null || true
  fi
  echo "OK: ACLs aplicadas (se suportado)."
else
  echo "AVISO: setfacl não disponível — verifique permissões manualmente."
fi

# 3) Reinicia rsyslog para garantir que as configs foram recarregadas (opcional)
echo
echo ">>> Reiniciando rsyslog para garantir imfile carregado (opcional)..."
sudo systemctl restart rsyslog || echo "WARN: falha ao reiniciar rsyslog (talvez não crítico)"
sleep ${WAIT_RSYSLOG_AFTER_RESTART}

# 4) Reinicia Wazuh manager (para carregar decoders/rules editados anteriormente) - opcional
echo
echo ">>> Reiniciando wazuh-manager (opcional, se você alterou decoders/rules recentemente)..."
sudo systemctl restart wazuh-manager || echo "WARN: falha ao reiniciar wazuh-manager"
sleep ${WAIT_WAZUH_AFTER_RESTART}

# 5) Limpar estado (opcional) para forçar releitura pelo logcollector (cuidado: remove estado global)
echo
echo ">>> Removendo arquivo de state do logcollector (/var/ossec/queue/ossec/logcollector.state) para forçar releitura (opcional)"
if [ -f /var/ossec/queue/ossec/logcollector.state ]; then
  sudo rm -f /var/ossec/queue/ossec/logcollector.state || true
  echo "OK: state removido."
else
  echo "OK: state não existe — pulando."
fi
sleep 2

# 6) Criar TAG única e injetar via msfconsole (não-interativo) E também escrever diretamente no host
TAG="WAGAO-VALIDOU-$(date +%s)"
MSG="[$TAG] WAGAO VALIDOU CADA ETAPA - TESTE AUTOMATIZADO"

echo
echo ">>> Injetando mensagem usando msfconsole dentro do container (spool -> echo -> spool off)"
# Use msfconsole -x to run commands non-interactively (se imagem suportar)
# Comandos: spool <file>; exec echo "xxx"; spool off; exit
MSF_COMMANDS="spool /root/.msf4/logs/console_audit.log; exec echo \"$(date -Iseconds) ${MSG}\"; spool off; exit"
echo "DEBUG: msfcommands => ${MSF_COMMANDS}"

set +e
docker exec "${METASP_CONTAINER}" /usr/src/metasploit-framework/msfconsole -x "${MSF_COMMANDS}" >/tmp/msf_exec.out 2>&1
MSF_RC=$?
set -e
if [ ${MSF_RC} -ne 0 ]; then
  echo "WARN: msfconsole retornou código ${MSF_RC}. Veja /tmp/msf_exec.out para saída."
else
  echo "OK: Comando msfconsole executado (ver /tmp/msf_exec.out para saída)."
fi

# As vezes é útil também escrever diretamente no arquivo host (simula spool)
echo ">>> Também escrevendo diretamente no arquivo bind-mounted do host para garantia"
sudo sh -c "echo \"$(date -Iseconds) ${MSG}\" >> ${HOST_ORIG_FILE}"

# 7) Aguarda e verifica se rsyslog copiou para /var/log/metasploit/framework.log
echo
echo ">>> Aguardando replicação do rsyslog para ${RSYSLOG_DEST_FILE} (timeout ${TIMEOUT_SHORT}s)..."
SEEN=0
for i in $(seq 1 ${TIMEOUT_SHORT}); do
  if sudo grep -q "${TAG}" "${RSYSLOG_DEST_FILE}" 2>/dev/null; then
    SEEN=1
    break
  fi
  sleep 1
done

if [ ${SEEN} -eq 1 ]; then
  echo "OK: rsyslog replicou a linha para ${RSYSLOG_DEST_FILE}"
  echo "Últimas linhas contendo a TAG:"
  sudo tail -n 10 "${RSYSLOG_DEST_FILE}" | grep "${TAG}" -n || true
else
  echo "ERRO: rsyslog NÃO replicou a linha dentro de ${TIMEOUT_SHORT}s. Verifique imfile/containers.conf/perms."
  echo "Mostrando últimas 50 linhas de journal do rsyslog:"
  sudo journalctl -u rsyslog -n 50 --no-pager
  exit 2
fi

# 8) Verificar se o Wazuh Logcollector está analisando o arquivo
echo
echo ">>> Verificando se Wazuh logcollector está monitorando o arquivo destino..."
if sudo grep -i "Analyzing file" "${WAZUH_OSSEC_LOG}" | grep -q "$(basename ${RSYSLOG_DEST_FILE} | sed 's/.log//')"; then
  echo "OK: logcollector indica que analisa arquivos relacionados."
else
  echo "INFO: procure por 'Analyzing file' no ${WAZUH_OSSEC_LOG} manualmente (pode demorar)."
fi

# 9) Aguarda processamento do Wazuh e busca no alerts.json
echo
echo ">>> Aguardando criação de alerta no ${WAZUH_ALERTS_JSON} (timeout ${TIMEOUT_MED}s)..."
FOUND=0
for i in $(seq 1 ${TIMEOUT_MED}); do
  if sudo tail -n 500 "${WAZUH_ALERTS_JSON}" 2>/dev/null | grep -q "${TAG}"; then
    FOUND=1
    break
  fi
  sleep 1
done

if [ ${FOUND} -eq 1 ]; then
  echo "OK: alerta gerado em ${WAZUH_ALERTS_JSON}"
  sudo tail -n 200 "${WAZUH_ALERTS_JSON}" | grep -n "${TAG}" -n || true
  echo
  echo "Exibindo o JSON completo (primeira ocorrência):"
  sudo tail -n 500 "${WAZUH_ALERTS_JSON}" | grep -n -m1 "${TAG}" -n -B5 -A10 || true
else
  echo "ERRO: alerta com tag ${TAG} não encontrado em ${WAZUH_ALERTS_JSON} dentro de ${TIMEOUT_MED}s."
  echo "Dicas: verifique se o decoder/rule estão carregados e se o Wazuh manager está rodando."
  echo "Mostre os últimos logs do wazuh:"
  sudo tail -n 200 "${WAZUH_OSSEC_LOG}" || true
  exit 3
fi

# 10) Opcional: testar decodificação com wazuh-logtest (local)
echo
echo ">>> Opcional: rodar wazuh-logtest com a linha extraída do rsyslog (se disponível)"
SAMPLE_LINE=$(sudo grep "${TAG}" "${RSYSLOG_DEST_FILE}" | tail -n 1 || true)
if [ -n "${SAMPLE_LINE}" ] && [ -x "${WAZUH_LOGTEST}" ]; then
  echo "Linha de exemplo: ${SAMPLE_LINE}"
  echo "Executando wazuh-logtest (manual):"
  echo "${SAMPLE_LINE}" | sudo ${WAZUH_LOGTEST}
else
  echo "Ignorando wazuh-logtest (linha não encontrada ou wazuh-logtest não disponível)."
fi

echo
echo "=== TESTE CONCLUÍDO ==="
date
echo "Resumo rápido:"
echo " - Tag usada: ${TAG}"
echo " - Arquivo de origem (host): ${HOST_ORIG_FILE}"
echo " - Arquivo destino rsyslog: ${RSYSLOG_DEST_FILE}"
echo " - Alerts: ver ${WAZUH_ALERTS_JSON} (grep ${TAG})"
echo
echo "Se quiser, copie este script para /usr/local/bin e reutilize nos testes."
