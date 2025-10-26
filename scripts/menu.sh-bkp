#!/bin/bash
set -euo pipefail

SCRIPTS_PATH="/opt/ngsoc-deploy/scripts"
WIDTH=90
HEIGHT=35

# ===============================
# Tela de boas-vindas
# ===============================
show_welcome() {
    NGSOC_ASCII=$(figlet -f big "NGSOC" 2>/dev/null || echo "NGSOC")
    POSITIVOS_ASCII=$(figlet -f small "POSITIVOS+" 2>/dev/null || echo "POSITIVOS+")

    center_text() {
        local line="$1"
        local len=${#line}
        local pad=$(( (WIDTH - len) / 2 ))
        printf "%*s%s\n" $pad "" "$line"
    }

    CENTERED_ASCII=$(echo "$NGSOC_ASCII" | while IFS= read -r line; do center_text "$line"; done)
    CENTERED_POSITIVOS=$(echo "$POSITIVOS_ASCII" | while IFS= read -r line; do center_text "$line"; done)

    WELCOME_MSG="Bem-vindo ao NGSOC - OpenSource SOC\nConfigure e gerencie suas ferramentas de monitoramento e pentest."
    CENTERED_MSG=$(echo -e "$WELCOME_MSG" | while IFS= read -r line; do center_text "$line"; done)

    LINE_LARGE=$(printf '=%.0s' $(seq 1 $WIDTH))
    LINE_MEDIUM=$(printf -- '-%.0s' $(seq 1 $((WIDTH/2))))
    LINE_SMALL=$(printf -- '.%.0s' $(seq 1 $((WIDTH/4))))

    FOOTER="© 2025 POSITIVOS+. Todos os direitos reservados. Licença: MIT"

    ASCII_ART="$CENTERED_ASCII\n$CENTERED_POSITIVOS\n$LINE_LARGE\n$CENTERED_MSG\n$LINE_MEDIUM\n$LINE_SMALL\n$FOOTER"

    whiptail --title "NGSOC - Bem-vindo" --msgbox "$ASCII_ART" $HEIGHT $WIDTH --ok-button "INICIAR"
}

# ===============================
# Menu Principal
# ===============================
main_menu() {
    while true; do
        CHOICE=$(whiptail --title "NGSOC - Menu Principal" --menu "Escolha uma opção" $HEIGHT $WIDTH 12 \
            "1" "Pré-requisitos" \
            "2" "Implantação" \
            "3" "Gestão" \
            "4" "Portais" \
            "5" "Estrutura de diretórios" \
            "0" "Sair" 3>&1 1>&2 2>&3)

        case $CHOICE in
            1) prerequisites_menu ;;
            2) deployment_menu ;;
            3) gestion_menu ;;
            4) portals_menu ;;
            5) directory_structure ;;
            0) exit 0 ;;
            *) whiptail --msgbox "Opção inválida" 8 40 ;;
        esac
    done
}

# ===============================
# Pré-requisitos
# ===============================
prerequisites_menu() {
    while true; do
        CHOICE=$(whiptail --title "Pré-requisitos" --menu "Escolha uma opção" 20 78 10 \
            "1" "Instalar Básicos" \
            "2" "Instalar Docker" \
            "3" "Instalar Ansible" \
            "0" "VOLTAR" 3>&1 1>&2 2>&3)

        case $CHOICE in
            1) bash "$SCRIPTS_PATH/install_basics.sh" ;;
            2) bash "$SCRIPTS_PATH/install_docker.sh" ;;
            3) bash "$SCRIPTS_PATH/install_ansible.sh" ;;
            0) break ;;
            *) whiptail --msgbox "Opção inválida" 8 40 ;;
        esac
    done
}

# ===============================
# Implantação
# ===============================
deployment_menu() {
    while true; do
        CHOICE=$(whiptail --title "Implantação" --menu "Escolha um componente para instalar" 20 78 10 \
            "1" "Wazuh" \
            "2" "OpenVAS / GVM" \
            "3" "MITMProxy" \
            "4" "Trivy" \
            "5" "MongoDB" \
            "6" "Harbor" \
            "7" "OWASP ZAP" \
            "0" "VOLTAR" 3>&1 1>&2 2>&3)

        case $CHOICE in
            1) bash "$SCRIPTS_PATH/install_wazuh_full.sh" ;;
            2) bash "$SCRIPTS_PATH/install_openvas_docker.sh-testar" ;;
            3) bash "$SCRIPTS_PATH/install_mitmproxy_docker.sh" ;;
            4) bash "$SCRIPTS_PATH/install_trivy_docker.sh" ;;
            5) bash "$SCRIPTS_PATH/install_mongodb_docker.sh" ;;
            6) bash "$SCRIPTS_PATH/install_harbor.sh" ;;
            7) bash "$SCRIPTS_PATH/install_zap_docker.sh" ;;
            0) break ;;
            *) whiptail --msgbox "Opção inválida" 8 40 ;;
        esac
    done
}

# ===============================
# Gestão
# ===============================
gestion_menu() {
    while true; do
        CHOICE=$(whiptail --title "Gestão" --menu "Escolha uma opção" 20 78 12 \
            "1" "Status Serviços e Containers" \
            "2" "Restart Wazuh" \
            "3" "Restart Containers por Componente" \
            "0" "VOLTAR" 3>&1 1>&2 2>&3)

        case $CHOICE in
            1) show_status ;;         # agora seguro
            2) restart_wazuh ;;
            3) restart_containers_menu ;;
            0) break ;;
            *) whiptail --msgbox "Opção inválida" 8 40 ;;
        esac
    done
}

# ===============================
# Status (corrigido para não abortar em grep vazio)
# ===============================
show_status() {
    local STATUS_TEXT
    STATUS_TEXT=$(mktemp)
    local H=28
    local W=88

    # WAZUH services
    {
        echo "==== WAZUH Services ===="
        for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do
            if systemctl is-active --quiet "$svc"; then
                printf "  [%s] ✅ UP\n" "$svc"
            else
                printf "  [%s] ❌ DOWN\n" "$svc"
            fi
        done
        echo ""
    } > "$STATUS_TEXT"

    # Map of tools -> patterns (adjust patterns to your real container names if needed)
    declare -A TOOLS
    TOOLS["OpenVAS"]="greenbone-community|gvm-official|openvas"
    TOOLS["MITMProxy"]="ngsoc_mitmproxy|mitmproxy"
    TOOLS["Trivy"]="ngsoc_trivy|trivy"
    TOOLS["MongoDB"]="ngsoc_mongodb|mongodb|msf-db"
    TOOLS["Harbor"]="harbor|registry|registryctl|harbor-core|harbor-db|harbor-log|harbor-portal|harbor-jobservice|redis"
    TOOLS["OWASP ZAP"]="ngsoc_zap|zap"

    # Capture docker ps once
    DOCKER_LIST=$(docker ps -a --format "{{.Names}}\t{{.Status}}" 2>/dev/null || true)

    for TOOL in OpenVAS MITMProxy Trivy MongoDB Harbor "OWASP ZAP"; do
        pattern="${TOOLS[$TOOL]}"
        echo "==== $TOOL Containers ====" >> "$STATUS_TEXT"
        # use grep -E with || true to avoid non-zero exit
        matches=$(printf "%s\n" "$DOCKER_LIST" | grep -E "$pattern" || true)
        if [ -z "$matches" ]; then
            echo "  (nenhum container encontrado para $TOOL)" >> "$STATUS_TEXT"
        else
            while IFS=$'\n' read -r line; do
                # line format: name<TAB>status
                name=$(printf "%s" "$line" | cut -f1)
                status=$(printf "%s" "$line" | cut -f2-)
                if [[ "$status" == Up* ]]; then
                    echo "  [$name] ✅ $status" >> "$STATUS_TEXT"
                else
                    echo "  [$name] ❌ $status" >> "$STATUS_TEXT"
                fi
            done <<< "$matches"
        fi
        echo "" >> "$STATUS_TEXT"
    done

    # show in scrollable textbox and then return (no exit)
    whiptail --title "Status dos Serviços e Containers" --scrolltext --textbox "$STATUS_TEXT" $H $W
    rm -f "$STATUS_TEXT"
    return 0
}

# ===============================
# Restart Wazuh
# ===============================
restart_wazuh() {
    for svc in wazuh-manager wazuh-indexer wazuh-dashboard; do
        if systemctl list-unit-files --type=service | grep -q "^$svc"; then
            systemctl restart "$svc" || true
        fi
    done
    whiptail --msgbox "Serviços Wazuh reiniciados (se existiam)." 8 50
}

# ===============================
# Restart Containers (seguro)
# ===============================
restart_containers_menu() {
    local RESTARTED=false
    while true; do
        CHOICE=$(whiptail --title "Restart Containers" --menu "Escolha um componente" 20 78 10 \
            "1" "OpenVAS / GVM" \
            "2" "MITMProxy" \
            "3" "Trivy" \
            "4" "MongoDB" \
            "5" "Harbor" \
            "6" "OWASP ZAP" \
            "0" "VOLTAR" 3>&1 1>&2 2>&3)

        case $CHOICE in
            1)
                conts=$(docker ps -a --format '{{.Names}}' --filter "name=gvm" 2>/dev/null || true)
                if [ -n "$conts" ]; then docker restart $conts && RESTARTED=true; else whiptail --msgbox "Nenhum container OpenVAS encontrado." 8 60; fi
                ;;
            2)
                conts=$(docker ps -a --format '{{.Names}}' --filter "name=ngsoc_mitmproxy" 2>/dev/null || true)
                if [ -n "$conts" ]; then docker restart $conts && RESTARTED=true; else whiptail --msgbox "Nenhum container MITMProxy encontrado." 8 60; fi
                ;;
            3)
                conts=$(docker ps -a --format '{{.Names}}' --filter "name=trivy" 2>/dev/null || true)
                if [ -n "$conts" ]; then docker restart $conts && RESTARTED=true; else whiptail --msgbox "Nenhum container Trivy encontrado." 8 60; fi
                ;;
            4)
                conts=$(docker ps -a --format '{{.Names}}' --filter "name=mongodb" 2>/dev/null || true)
                if [ -n "$conts" ]; then docker restart $conts && RESTARTED=true; else whiptail --msgbox "Nenhum container MongoDB encontrado." 8 60; fi
                ;;
            5)
                conts=$(docker ps -a --format '{{.Names}}' --filter "name=harbor" 2>/dev/null || true)
                if [ -n "$conts" ]; then docker restart $conts && RESTARTED=true; else whiptail --msgbox "Nenhum container Harbor encontrado." 8 60; fi
                ;;
            6)
                conts=$(docker ps -a --format '{{.Names}}' --filter "name=zap" 2>/dev/null || true)
                if [ -n "$conts" ]; then docker restart $conts && RESTARTED=true; else whiptail --msgbox "Nenhum container ZAP encontrado." 8 60; fi
                ;;
            0) break ;;
            *) whiptail --msgbox "Opção inválida" 8 40 ;;
        esac
    done

    if [ "$RESTARTED" = true ]; then
        whiptail --msgbox "Containers reiniciados!" 8 50
    fi
}

# ===============================
# Portais
# ===============================
portals_menu() {
    while true; do
        CHOICE=$(whiptail --title "Portais" --menu "Escolha um portal" 20 78 10 \
            "1" "OWASP ZAP" \
            "2" "OPENVAS" \
            "3" "MITMProxy" \
            "4" "Wazuh Dashboard" \
            "5" "TRIVY" \
            "6" "Harbor" \
            "0" "VOLTAR" 3>&1 1>&2 2>&3)

        case $CHOICE in
            1) xdg-open "http://192.168.100.23:8080" 2>/dev/null || whiptail --msgbox "URL: http://192.168.100.23:8080" 8 60 ;;
            2) xdg-open "http://192.168.100.23:9392/login" 2>/dev/null || whiptail --msgbox "URL: http://192.168.100.23:9392/login" 8 60 ;;
            3) xdg-open "http://192.168.100.23:8090/#/flows" 2>/dev/null || whiptail --msgbox "URL: http://192.168.100.23:8090/#/flows" 8 60 ;;
            4) xdg-open "https://localhost:443" 2>/dev/null || whiptail --msgbox "URL: https://localhost:443" 8 60 ;;
            5) xdg-open "http://192.168.100.23:4954/" 2>/dev/null || whiptail --msgbox "URL: http://192.168.100.23:4954/" 8 60 ;;
            6) xdg-open "https://harbor.local:8443/" 2>/dev/null || whiptail --msgbox "URL: https://harbor.local:8443/" 8 60 ;;
            0) break ;;
            *) whiptail --msgbox "Opção inválida" 8 40 ;;
        esac
    done
}

# ===============================
# Estrutura de diretórios
# ===============================
directory_structure() {
    local DIR_TEXT
    DIR_TEXT=$(mktemp)
    cat <<EOT > "$DIR_TEXT"
/opt/ngsoc-deploy
├── Ansible
│   └── playbooks
│       ├── deploy_harbor.yml
│       ├── deploy_mitmproxy.yml
│       ├── deploy_mongodb.yml
│       ├── deploy_nginx_exports.yml
│       ├── deploy_openvas.yml-testar
│       ├── deploy_trivy.yml
│       ├── deploy_wazuh.yml
│       ├── deploy_metasploite.yml
│       └── deploy_zap.yml
├── data
│   ├── harbor
│   ├── mongodb
│   ├── trivy
│   └── mitmproxy
├── docs
├── exports
└── scripts
EOT

    whiptail --title "Estrutura de Diretórios" --scrolltext --textbox "$DIR_TEXT" 25 80
    rm -f "$DIR_TEXT"
}

# ===============================
# Execução
# ===============================
show_welcome
main_menu
