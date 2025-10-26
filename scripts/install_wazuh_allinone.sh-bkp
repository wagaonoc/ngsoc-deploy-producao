#!/bin/bash
set -Eeuo pipefail

# =========================
# VARIÁVEIS
# =========================
VT_API_KEY="${VT_API_KEY:-}"              # export VT_API_KEY="sua_chave" antes de rodar (ou edite aqui)
READMEDIR="/opt/ngsoc-deploy/docs/wazuh"
READMefile="$READMEDIR/README.txt"
LOGDIR="/opt/ngsoc-deploy/logs/wazuh"
SCRIPTSDIR="/opt/ngsoc-deploy/scripts"
PLAYBOOKDIR="/opt/ngsoc-deploy/Ansible/playbooks"
OSSEC_CONF="/var/ossec/etc/ossec.conf"
LOCAL_RULES="/var/ossec/etc/rules/local_rules.xml"
LOCAL_DECODERS="/var/ossec/etc/decoders/local_decoder.xml"
VT_WRAPPER="/var/ossec/integrations/virustotal"
VT_PY="/var/ossec/integrations/virustotal.py"

# =========================
# FUNÇÕES AUXILIARES
# =========================
fail() { echo "❌ ERRO: $*" >&2; exit 1; }
trap 'fail "Instalação falhou (veja logs em /var/ossec/logs/ossec.log)."' ERR

msg() { echo -e "$*"; }

get_ip() { hostname -I 2>/dev/null | awk '{print $1}'; }

require_root() { [ "$EUID" -eq 0 ] || fail "Execute como root (sudo)."; }

# =========================
# PRÉ-CHECKS
# =========================
require_root
mkdir -p "$READMEDIR" "$LOGDIR" "$SCRIPTSDIR" "$PLAYBOOKDIR"

if [[ -z "${VT_API_KEY}" ]]; then
  msg "⚠️  VT_API_KEY não definido; integração VirusTotal será configurada mas pode não responder até definir a chave."
fi

# =========================
# REPOSITÓRIO & PACOTES
# =========================
msg "📦 Instalando Wazuh (manager, indexer, dashboard) e dependências..."
apt-get update -y
# Repo oficial (ajuste se já tiver configurado):
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update -y

# Pacotes principais
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  wazuh-manager wazuh-indexer wazuh-dashboard jq curl openssl

# =========================
# PARAR SERVIÇOS PARA CONFIGURAR
# =========================
systemctl stop wazuh-manager || true

# =========================
# CONFIG: ossec.conf
# =========================
msg "📝 Gravando ${OSSEC_CONF}..."
cat > "$OSSEC_CONF" <<"EOF"
<!-- Wazuh - Manager Configuration -->
<ossec_config>
  <global>
    <jsonout_output>yes</jsonout_output>
    <alerts_log>yes</alerts_log>
    <logall>no</logall>
    <logall_json>no</logall_json>
    <email_notification>no</email_notification>
    <smtp_server>smtp.example.wazuh.com</smtp_server>
    <email_from>wazuh@example.wazuh.com</email_from>
    <email_to>recipient@example.wazuh.com</email_to>
    <email_maxperhour>12</email_maxperhour>
    <email_log_source>alerts.log</email_log_source>
    <agents_disconnection_time>15m</agents_disconnection_time>
    <agents_disconnection_alert_time>0</agents_disconnection_alert_time>
    <update_check>yes</update_check>
  </global>

  <alerts>
    <log_alert_level>1</log_alert_level>
    <email_alert_level>12</email_alert_level>
  </alerts>

  <logging>
    <log_format>plain</log_format>
  </logging>

  <remote>
    <connection>secure</connection>
    <port>1514</port>
  </remote>

  <!-- Integração com VirusTotal -->
  <integration>
    <name>virustotal</name>
    <api_key>__VT_API_KEY_PLACEHOLDER__</api_key>
    <group>syscheck,syscheck_file,syscheck_entry_added,syscheck_entry_modified,syscheck_entry_deleted</group>
    <alert_format>json</alert_format>
  </integration>

  <!-- Rootcheck -->
  <rootcheck>
    <disabled>no</disabled>
    <check_files>yes</check_files>
    <check_trojans>yes</check_trojans>
    <check_dev>yes</check_dev>
    <check_sys>yes</check_sys>
    <check_pids>yes</check_pids>
    <check_ports>yes</check_ports>
    <check_if>yes</check_if>
    <frequency>43200</frequency>
    <rootkit_files>etc/rootcheck/rootkit_files.txt</rootkit_files>
    <rootkit_trojans>etc/rootcheck/rootkit_trojans.txt</rootkit_trojans>
    <skip_nfs>yes</skip_nfs>
    <ignore>/var/lib/containerd</ignore>
    <ignore>/var/lib/docker/overlay2</ignore>
  </rootcheck>

  <!-- Wodles -->
  <wodle name="syscollector">
    <disabled>no</disabled>
    <interval>1h</interval>
    <scan_on_start>yes</scan_on_start>
    <hardware>yes</hardware>
    <os>yes</os>
    <network>yes</network>
    <packages>yes</packages>
    <ports all="yes">yes</ports>
    <processes>yes</processes>
    <synchronization>
      <max_eps>10</max_eps>
    </synchronization>
  </wodle>

  <sca>
    <enabled>yes</enabled>
    <scan_on_start>yes</scan_on_start>
    <interval>12h</interval>
    <skip_nfs>yes</skip_nfs>
  </sca>

  <vulnerability-detection>
    <enabled>yes</enabled>
    <index-status>yes</index-status>
    <feed-update-interval>60m</feed-update-interval>
  </vulnerability-detection>

  <!-- Syscheck -->
  <syscheck>
    <disabled>no</disabled>
    <frequency>43200</frequency>
    <scan_on_start>yes</scan_on_start>
    <alert_new_files>yes</alert_new_files>
    <auto_ignore frequency="10" timeframe="3600">no</auto_ignore>

    <!-- Diretórios monitorados -->
    <directories realtime="yes">/etc,/usr/bin,/usr/sbin,/usr/local/bin,/bin,/sbin,/boot</directories>

    <!-- Exclusões e filtros -->
    <ignore>/etc/mtab</ignore>
    <ignore>/etc/hosts.deny</ignore>
    <ignore type="sregex">.log$|.swp$</ignore>
    <nodiff>/etc/ssl/private.key</nodiff>

    <!-- Otimizações -->
    <skip_nfs>yes</skip_nfs>
    <skip_dev>yes</skip_dev>
    <skip_proc>yes</skip_proc>
    <skip_sys>yes</skip_sys>
    <process_priority>10</process_priority>
    <max_eps>50</max_eps>

    <!-- Sincronização -->
    <synchronization>
      <enabled>yes</enabled>
      <interval>5m</interval>
      <max_eps>10</max_eps>
    </synchronization>
  </syscheck>

  <!-- Coleta de logs locais -->
  <localfile>
    <log_format>syslog</log_format>
    <location>/var/ossec/logs/active-responses.log</location>
  </localfile>

  <localfile>
    <log_format>syslog</log_format>
    <location>/var/log/dpkg.log</location>
  </localfile>

  <!-- VirusTotal: integrações.log para virar evento -->
  <localfile>
    <location>/var/ossec/logs/integrations.log</location>
    <log_format>syslog</log_format>
  </localfile>

  <localfile>
    <location>/var/log/harbor/core.log</location>
    <log_format>syslog</log_format>
  </localfile>

  <localfile>
    <location>/var/log/openvas/openvas.log</location>
    <log_format>syslog</log_format>
  </localfile>

  <localfile>
    <location>/var/log/openvas/ospd-openvas.log</location>
    <log_format>syslog</log_format>
  </localfile>

  <localfile>
    <location>/var/log/metasploit/framework.log</location>
    <log_format>syslog</log_format>
  </localfile>

  <localfile>
    <location>/var/log/mitmproxy/mitmproxy.log</location>
    <log_format>syslog</log_format>
  </localfile>

  <localfile>
    <location>/var/log/zap/zap.log</location>
    <log_format>syslog</log_format>
  </localfile>

  <localfile>
    <location>/var/log/trivy/trivy-server.log</location>
    <log_format>syslog</log_format>
  </localfile>

  <!-- Ruleset -->
  <ruleset>
    <decoder_dir>ruleset/decoders</decoder_dir>
    <rule_dir>ruleset/rules</rule_dir>
    <decoder_dir>etc/decoders</decoder_dir>
    <rule_dir>etc/rules</rule_dir>
  </ruleset>

</ossec_config>
EOF

# inserir API key se houver
if [[ -n "${VT_API_KEY}" ]]; then
  sed -i "s#__VT_API_KEY_PLACEHOLDER__#${VT_API_KEY}#g" "$OSSEC_CONF"
else
  sed -i "s#__VT_API_KEY_PLACEHOLDER__#REPLACE_ME#g" "$OSSEC_CONF"
fi

# =========================
# CONFIG: local_rules.xml
# =========================
msg "📝 Gravando ${LOCAL_RULES}..."
cat > "$LOCAL_RULES" <<"EOF"
<!-- ========== Harbor Rules ========== -->
<group name="harbor-rules">
  <rule id="100900" level="7">
    <decoded_as>harbor-core-json</decoded_as>
    <description>Harbor core: falha de autenticação (401)</description>
    <regex field="status">401</regex>
  </rule>
  <rule id="100901" level="8">
    <decoded_as>harbor-core-json</decoded_as>
    <description>Harbor core: acesso proibido (403)</description>
    <regex field="status">403</regex>
  </rule>
  <rule id="100902" level="10">
    <decoded_as>harbor-core-json</decoded_as>
    <description>Harbor core: erro interno (500)</description>
    <regex field="status">500</regex>
  </rule>
  <rule id="100903" level="10">
    <decoded_as>harbor-core-json</decoded_as>
    <regex field="method">DELETE</regex>
    <description>ALERTA CRÍTICO: Artefato/Imagem DELETADO(A) do Harbor - Usuário: $(operator)</description>
  </rule>
  <rule id="100910" level="0">
    <decoded_as>harbor-jobservice-json</decoded_as>
    <description>Harbor jobservice: status 200</description>
    <regex field="status">200</regex>
  </rule>
  <rule id="100911" level="7">
    <decoded_as>harbor-jobservice-json</decoded_as>
    <description>Harbor jobservice: erro</description>
    <regex field="status">[^2]..\d</regex>
  </rule>
  <rule id="100920" level="5">
    <decoded_as>trivy-adapter-json</decoded_as>
    <description>Harbor Trivy: status 200</description>
    <regex field="status">200</regex>
  </rule>
  <rule id="100921" level="7">
    <decoded_as>trivy-adapter-json</decoded_as>
    <description>Harbor Trivy: erro</description>
    <regex field="status">[^2]..\d</regex>
  </rule>
</group>

<!-- ========== Metasploit Rules ========== -->
<group name="metasploit-rules">
  <rule id="101000" level="5">
    <decoded_as>metasploit-audit</decoded_as>
    <description>Metasploit: evento detectado</description>
  </rule>
  <rule id="101001" level="7">
    <decoded_as>metasploit-audit</decoded_as>
    <match>Spooling to file</match>
    <description>Metasploit: início de sessão de console / spool de saída</description>
  </rule>
  <rule id="101002" level="10">
    <decoded_as>metasploit-audit</decoded_as>
    <match>Meterpreter session opened</match>
    <description>Metasploit: sessão Meterpreter aberta</description>
  </rule>
  <rule id="101003" level="5">
    <decoded_as>metasploit-audit</decoded_as>
    <match>Meterpreter session closed</match>
    <description>Metasploit: sessão Meterpreter finalizada</description>
  </rule>
  <rule id="101004" level="10">
    <decoded_as>metasploit-audit</decoded_as>
    <match>Exploit completed, result: success</match>
    <description>Metasploit: exploit completado com sucesso</description>
  </rule>
  <rule id="101005" level="8">
    <decoded_as>metasploit-audit</decoded_as>
    <match>(Uploading:|Wrote:|Saved payload to)</match>
    <description>Metasploit: upload ou gravação de payload detectado</description>
  </rule>
</group>

<!-- Mitmproxy -->
<group name="mitmproxy-rules">
  <rule id="101100" level="7">
    <decoded_as>mitmproxy-audit</decoded_as>
    <description>Mitmproxy: teste REAL detectado (marca MITM-WAZUH-REAL)</description>
  </rule>
</group>

<!-- ========== OWASP ZAP ========== -->
<group name="zap-rules">
  <rule id="110300" level="5">
    <decoded_as>zap-audit</decoded_as>
    <description>OWASP ZAP: evento detectado no log</description>
  </rule>
  <rule id="110301" level="10">
    <decoded_as>zap-audit</decoded_as>
    <match>ERROR</match>
    <description>OWASP ZAP: erro detectado no log</description>
  </rule>
</group>

<!-- ========== Trivy ========== -->
<group name="trivy-rules">
  <rule id="120100" level="5">
    <decoded_as>trivy-audit</decoded_as>
    <match>[INFO]</match>
    <description>Trivy: scan informativo</description>
  </rule>
  <rule id="120101" level="7">
    <decoded_as>trivy-audit</decoded_as>
    <match>[WARN]</match>
    <description>Trivy: vulnerabilidade detectada</description>
  </rule>
  <rule id="120102" level="10">
    <decoded_as>trivy-audit</decoded_as>
    <match>[ERROR]</match>
    <description>Trivy: erro crítico no motor de scan</description>
  </rule>
</group>

<!-- ========== Greenbone / OpenVAS / OSPD ========== -->
<group name="greenbone-rules">
  <rule id="130000" level="5">
    <decoded_as>greenbone-audit</decoded_as>
    <description>Greenbone/OpenVAS: evento genérico detectado</description>
  </rule>
  <rule id="130001" level="7">
    <decoded_as>greenbone-audit</decoded_as>
    <match>Failed</match>
    <description>Greenbone/OpenVAS: falha detectada</description>
  </rule>
  <rule id="130002" level="8">
    <decoded_as>greenbone-audit</decoded_as>
    <match>Connection refused</match>
    <description>Greenbone/OpenVAS: conexão com scanner recusada</description>
  </rule>
  <rule id="130003" level="10">
    <decoded_as>greenbone-audit</decoded_as>
    <match>CRITICAL</match>
    <description>Greenbone/OpenVAS: erro crítico</description>
  </rule>
  <rule id="130004" level="3">
    <decoded_as>openvas-audit</decoded_as>
    <match>started</match>
    <description>OpenVAS Scanner: início de varredura</description>
  </rule>
  <rule id="130005" level="5">
    <decoded_as>openvas-audit</decoded_as>
    <match>finished</match>
    <description>OpenVAS Scanner: varredura concluída</description>
  </rule>
  <rule id="130006" level="10">
    <decoded_as>openvas-audit</decoded_as>
    <match>database is locked</match>
    <description>OpenVAS: erro de banco de dados bloqueado</description>
  </rule>
</group>

<group name="greenbone-rules,ospd">
  <rule id="130010" level="3">
    <decoded_as>greenbone-ospd-log</decoded_as>
    <description>Greenbone OSPD: evento informativo</description>
    <options>no_full_log</options>
    <match>INFO</match>
  </rule>
  <rule id="130011" level="7">
    <decoded_as>greenbone-ospd-log</decoded_as>
    <description>Greenbone OSPD: alerta WARNING</description>
    <match>WARN</match>
  </rule>
  <rule id="130012" level="10">
    <decoded_as>greenbone-ospd-log</decoded_as>
    <description>Greenbone OSPD: erro crítico</description>
    <match>CRITICAL</match>
  </rule>
</group>

<!-- ========== VirusTotal -> a partir do integrations.log ========== -->
<group name="local">
  <rule id="100500" level="8">
    <decoded_as>virustotal-detection</decoded_as>
    <description>VirusTotal: hash $(sha256) detectado por $(detections)/$(total) mecanismos</description>
    <group>virustotal,malware</group>
  </rule>
  <rule id="100501" level="4">
    <decoded_as>virustotal-warning</decoded_as>
    <description>VirusTotal: hash $(sha256) não encontrado ou limite da API atingido</description>
    <group>virustotal,info</group>
  </rule>
</group>
EOF

# =========================
# CONFIG: local_decoder.xml
# =========================
msg "📝 Gravando ${LOCAL_DECODERS}..."
cat > "$LOCAL_DECODERS" <<"EOF"
<!-- ========== Harbor Core / JobService / Trivy Decoders ========== -->
<decoder name="harbor-core-json">
  <prematch>harbor-core </prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>

<decoder name="harbor-jobservice-json">
  <prematch>harbor-jobservice </prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>

<decoder name="trivy-adapter-json">
  <prematch>harbor-trivy </prematch>
  <plugin_decoder>JSON_Decoder</plugin_decoder>
</decoder>

<!-- ========== Metasploit Decoder ========== -->
<decoder name="metasploit-audit">
  <prematch>metasploit</prematch>
  <regex>^[^\s]+\s+[0-9]+\s+[0-9]{2}:[0-9]{2}:[0-9]{2}\s+[^\s]+\s+metasploit\s+(.*)$</regex>
  <order>message</order>
</decoder>

<!-- ========== Mitmproxy Decoders ========== -->
<decoder name="mitmproxy-audit">
  <prematch>mitmproxy</prematch>
  <regex>^[A-Za-z]{3}\s+[0-9]{1,2}\s+[0-9:]{8}\s+[^\s]+\s+mitmproxy\s+(.*)$</regex>
  <order>message</order>
</decoder>

<decoder name="mitmproxy-audit-raw">
  <prematch>MITM-</prematch>
  <regex>^.*\\[MITM-[A-Z0-9-]+\\].*$</regex>
  <order>id</order>
</decoder>

<!-- ========== OWASP ZAP Decoder ========== -->
<decoder name="zap-audit">
  <prematch>zap</prematch>
  <regex>^(.*)$</regex>
  <order>message</order>
</decoder>

<!-- ========== Trivy Decoders (genéricos) ========== -->
<decoder name="trivy-audit">
  <prematch>trivy</prematch>
  <regex>^.*trivy.*$</regex>
  <order>message</order>
</decoder>
<decoder name="trivy-info">
  <prematch>trivy</prematch>
  <regex>[INFO]</regex>
  <order>level</order>
</decoder>
<decoder name="trivy-warn">
  <prematch>trivy</prematch>
  <regex>[WARN]</regex>
  <order>level</order>
</decoder>
<decoder name="trivy-error">
  <prematch>trivy</prematch>
  <regex>[ERROR]</regex>
  <order>level</order>
</decoder>

<!-- ========== Greenbone / OpenVAS / OSPD ========== -->
<decoder name="greenbone-audit">
  <prematch>greenbone</prematch>
  <regex>^[A-Za-z]{3}\s+[0-9]{1,2}\s+[0-9:]{8}\s+[^\s]+\s+greenbone\s+(.*)$</regex>
  <order>message</order>
</decoder>

<decoder name="openvas-audit">
  <prematch>openvas</prematch>
  <regex>^[A-Za-z]{3}\s+[0-9]{1,2}\s+[0-9:]{8}\s+[^\s]+\s+openvas\s+(.*)$</regex>
  <order>message</order>
</decoder>

<decoder name="greenbone-ospd-log">
  <prematch>OSPD</prematch>
  <regex>^OSPD[7]:\s*([A-Z]+):\s*(.*)$</regex>
  <order>level,message</order>
</decoder>

<!-- ========== VirusTotal no integrations.log ========== -->
<decoder name="virustotal-detection">
  <prematch>✅</prematch>
  <regex>^✅ ([a-fA-F0-9]{64}) detected by ([0-9]+) / ([0-9]+) engines$</regex>
  <order>sha256 detections total</order>
</decoder>

<decoder name="virustotal-warning">
  <prematch>⚠️</prematch>
  <regex>^⚠️ ([a-fA-F0-9]{64}) not found on VirusTotal or API limit reached$</regex>
  <order>sha256</order>
</decoder>
EOF

# =========================
# VIRUSTOTAL WRAPPER
# =========================
msg "🔗 Ajustando integração VirusTotal..."
cat > "$VT_WRAPPER" <<"EOF"
#!/bin/sh
# Wazuh - VirusTotal integration wrapper (ordem <alert_file> <api_key> ...)
ALERT_FILE="$1"
API_KEY="$2"

PYTHON="/var/ossec/framework/python/bin/python3"
SCRIPT="/var/ossec/integrations/virustotal.py"
[ ! -x "$PYTHON" ] && PYTHON="/usr/bin/python3"

if [ -f "$ALERT_FILE" ] && [ -n "$API_KEY" ]; then
  "$PYTHON" "$SCRIPT" -k "$API_KEY" -f "$ALERT_FILE"
else
  echo "Usage: virustotal <alert_file> <api_key> ..." >&2
  exit 1
fi
EOF

# Permissões recomendadas
chown root:wazuh "$VT_WRAPPER"
chmod 750 "$VT_WRAPPER"

# (Se o virustotal.py não existir, apenas avisa. Pacotes Wazuh geralmente trazem)
if [ ! -f "$VT_PY" ]; then
  msg "⚠️  $VT_PY não encontrado. Coloque o virustotal.py oficial aqui (mesma versão do Wazuh)."
fi

# =========================
# PERMISSÕES GERAIS
# =========================
msg "🔒 Ajustando permissões..."
chown root:wazuh "$OSSEC_CONF"
chmod 640 "$OSSEC_CONF"
chown wazuh:wazuh "$LOCAL_RULES" "$LOCAL_DECODERS"
chmod 640 "$LOCAL_RULES" "$LOCAL_DECODERS"
chown -R wazuh:wazuh /var/ossec/etc/shared /var/ossec/logs /var/ossec/queue
chmod 750 /var/ossec/{logs,queue,etc/shared}

# =========================
# VALIDAÇÃO DE SINTAXE
# =========================
msg "🧪 Validando configuração (wazuh-analysisd -t)..."
if ! /var/ossec/bin/wazuh-analysisd -t; then
  fail "Validação de configuração falhou."
fi

# =========================
# SUBIR SERVIÇOS
# =========================
msg "🚀 Subindo serviços..."
systemctl enable wazuh-manager wazuh-indexer wazuh-dashboard >/dev/null 2>&1 || true
systemctl restart wazuh-indexer wazuh-manager wazuh-dashboard

# =========================
# CRIAR/DEFINIR SENHA DO DASHBOARD
# =========================
msg "🔐 Definindo senha do usuário 'admin' no dashboard..."
DASH_PASS="$(openssl rand -base64 18 | tr -d '\n' )"
# Ferramenta oficial de senha do dashboard (ajuste ao path da sua instalação)
if command -v /usr/share/wazuh-dashboard/bin/wazuh-passwords-tool >/dev/null 2>&1; then
  /usr/share/wazuh-dashboard/bin/wazuh-passwords-tool --user admin --password "$DASH_PASS" >/dev/null
else
  msg "⚠️  wazuh-passwords-tool não encontrado; defina a senha do dashboard manualmente."
fi

# =========================
# README
# =========================
msg "📘 Gerando README..."
IP="$(get_ip)"
mkdir -p "$(dirname "$READMefile")"
cat > "$READMefile" <<EOF
==========================================================
NG-SOC - Wazuh (All-in-One) - Usage & Access
==========================================================
Dashboard URL : https://$IP:5601
Dashboard User: admin
Dashboard Pass: $DASH_PASS
----------------------------------------------------------
Serviços:
- wazuh-manager   (SIEM core)      : tcp/1514 (agents), tcp/55000 (API)
- wazuh-indexer   (OpenSearch)     : tcp/9200 (interno), 9300
- wazuh-dashboard (GUI)            : tcp/5601
----------------------------------------------------------
Diretórios importantes:
- /var/ossec/etc/ossec.conf
- /var/ossec/etc/rules/local_rules.xml
- /var/ossec/etc/decoders/local_decoder.xml
- /var/ossec/integrations/virustotal  (wrapper)
- /var/ossec/integrations/virustotal.py
- /var/ossec/logs/    (alerts, integrations, etc.)
- /var/ossec/queue/
----------------------------------------------------------
VirusTotal:
- API Key: ${VT_API_KEY:-REPLACE_ME}
- Eventos: /var/ossec/logs/integrations.log (coletado pelo ossec.conf)
- Alerta aparece no Dashboard (regras 100500/100501) quando o wrapper escrever:
  ✅ <sha256> detected by N / T engines
----------------------------------------------------------
Comandos úteis:
- Teste config:    sudo /var/ossec/bin/wazuh-analysisd -t
- Logs principais: sudo tail -n 50 /var/ossec/logs/ossec.log
                   sudo tail -n 50 /var/ossec/logs/integrations.log
- Reiniciar:       sudo systemctl restart wazuh-manager wazuh-indexer wazuh-dashboard
- Checar portas:   sudo ss -lntp | egrep '1514|55000|5601|9200|9300'
----------------------------------------------------------
Teste EICAR + VT:
echo -n "X5O!P%@AP[4\\PZX54(P^)7CC)7}\\\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\\\$H+H*" | sudo tee /usr/local/bin/eicar_vt.txt >/dev/null
sudo chmod 644 /usr/local/bin/eicar_vt.txt
# aguarde o syscheck gerar alerta; verifique:
sudo tail -f /var/ossec/logs/integrations.log
==========================================================
EOF

# =========================
# SAÍDA FINAL
# =========================
msg "=========================================================="
msg "✅ WAZUH: Instalação & Deploy concluídos com sucesso!"
msg "=========================================================="
msg "🔗 Dashboard: https://$IP:5601"
msg "👤 admin / 🔑 $DASH_PASS"
msg "📘 README: $READMefile"
