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
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --dearmor -o /usr/share/keyrings/wazuh.gpg
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt stable main" > /etc/apt/sources.list.d/wazuh.list
apt-get update -y

# Pacotes principais
DEBIAN_FRONTEND=noninteractive apt-get install -y \
  wazuh-manager wazuh-indexer wazuh-dashboard jq curl openssl ansible

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
# PERMISSÕES GERAIS E GRUPOS
# =========================
msg "🔒 Ajustando permissões..."
chown root:wazuh "$OSSEC_CONF"
chmod 640 "$OSSEC_CONF"
chown -R wazuh:wazuh /var/ossec/etc/shared /var/ossec/logs /var/ossec/queue || true
chmod 750 /var/ossec/{logs,queue,etc/shared} || true

# Adiciona wazuh aos grupos adm e syslog
if id wazuh &>/dev/null; then
  usermod -aG adm,syslog wazuh
  msg "✅ Usuário 'wazuh' adicionado aos grupos adm e syslog."
else
  msg "⚠️ Usuário 'wazuh' ainda não existe. Será criado durante instalação do pacote."
fi

# =========================
# VALIDAÇÃO DE SINTAXE
# =========================
msg "🧪 Validando configuração (wazuh-analysisd -t)..."
if ! /var/ossec/bin/wazuh-analysisd -t; then
  fail "Validação de configuração falhou."
fi

# =========================
# EXECUTAR DEPLOY VIA ANSIBLE
# =========================
msg "🚀 Executando deploy Wazuh via Ansible..."
if command -v ansible-playbook >/dev/null 2>&1; then
    ansible-playbook "$PLAYBOOKDIR/deploy_wazuh_allinone.yml" || fail "Falha ao executar o deploy via Ansible."
    msg "✅ Deploy Wazuh via Ansible concluído com sucesso!"
else
    msg "⚠️ Ansible não encontrado. Execute primeiro 'install_ansible.sh'."
    exit 1
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
DASH_PASS="$(openssl rand -base64 18 | tr -d '\n')"
if command -v /usr/share/wazuh-dashboard/bin/wazuh-passwords-tool >/dev/null 2>&1; then
  /usr/share/wazuh-dashboard/bin/wazuh-passwords-tool --user admin --password "$DASH_PASS" >/dev/null
else
  msg "⚠️  wazuh-passwords-tool não encontrado; defina a senha do dashboard manualmente."
fi

# =========================
# README FINAL
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
msg "=========================================================="
