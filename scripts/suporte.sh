#!/usr/bin/env bash
set -euo pipefail

# suporte.sh - NGSOC Suporte (Diagnóstico / Recuperação / Reinstalação)
# Mantém logs de suporte em /var/log/ngsoc-suporte/suporte.log

SCRIPTS_PATH="/opt/ngsoc-deploy/scripts"
WIDTH=90
HEIGHT=35
SUPORTE_DIR="/var/log/ngsoc-suporte"
SUPORTE_LOG="${SUPORTE_DIR}/suporte.log"

# cria diretório e arquivo de log (se necessário)
sudo mkdir -p "$SUPORTE_DIR"
sudo touch "$SUPORTE_LOG" 2>/dev/null || sudo touch "$SUPORTE_LOG"
sudo chmod 666 "$SUPORTE_LOG" 2>/dev/null || true

# -----------------------
# Utilitários
# -----------------------
list_logs_sorted() {
    local dir="$1"
    [ -d "$dir" ] || return 0
    # retorna caminhos completos ordenados por mod time
    find "$dir" -maxdepth 1 -type f -name '*.log' -printf '%T@ %p\n' 2>/dev/null | sort -n | awk '{print $2}'
}

containers_names_by_pattern() {
    local pattern="$1"
    docker ps -a --format "{{.Names}}" 2>/dev/null | grep -Ei "$pattern" || true
}

containers_info_by_pattern() {
    local pattern="$1"
    docker ps -a --format "{{.Names}}\t{{.Status}}" 2>/dev/null | grep -Ei "$pattern" || true
}

# restart a lista de containers (recebe lista de nomes via stdin) com gauge
restart_containers_with_gauge() {
    local tmpfile
    tmpfile=$(mktemp)
    local containers=()
    while IFS= read -r c; do
        [ -n "$c" ] && containers+=("$c")
    done

    local total=${#containers[@]}
    if [ "$total" -eq 0 ]; then
        echo "0" > "$tmpfile"
        echo "XXX" >> "$tmpfile"
        echo "0" >> "$tmpfile"
        echo "Nenhum container encontrado para reiniciar." >> "$tmpfile"
        cat "$tmpfile" | whiptail --gauge "Reiniciando containers..." 10 70 0
        rm -f "$tmpfile"
        return 0
    fi

    {
        pct=0
        step=$((100 / total))
        for cname in "${containers[@]}"; do
            pct=$((pct + step))
            [ "$pct" -gt 100 ] && pct=100
            echo "$pct"
            echo "XXX"
            echo "$pct"
            echo "Reiniciando $cname..."
            echo "XXX"
            # tentar reiniciar; não abortar se falhar
            if ! docker restart "$cname" >/dev/null 2>&1; then
                echo "Falha ao reiniciar $cname" >/dev/null
            fi
            # pausa curta para dar tempo aos containers para iniciar
            sleep 2
        done
        # garante 100%
        echo "100"
        echo "XXX"
        echo "100"
        echo "Reinício concluído."
    } | whiptail --gauge "Reiniciando containers..." 10 70 0

    rm -f "$tmpfile"
    return 0
}

show_file_if_exists() {
    local path="$1"
    local title="$2"
    if [ -f "$path" ]; then
        whiptail --title "$title" --scrolltext --textbox "$path" 25 90
    else
        whiptail --msgbox "$title\n\nArquivo não encontrado:\n$path" 10 70
    fi
}

# -----------------------
# Boas-vindas
# -----------------------
show_welcome() {
    clear
    NGSOC_ASCII=$(figlet -f big "NGSOC" 2>/dev/null || echo "NGSOC")
    POSITIVOS_ASCII=$(figlet -f small "POSITIVOS+" 2>/dev/null || echo "POSITIVOS+")

    center_text() {
        local line="$1"; local len=${#line}; local pad=$(( (WIDTH - len) / 2 ))
        [ "$pad" -lt 0 ] && pad=0
        printf "%*s%s\n" "$pad" "" "$line"
    }

    CENTERED_ASCII=$(echo "$NGSOC_ASCII" | while IFS= read -r l; do center_text "$l"; done)
    CENTERED_POSITIVOS=$(echo "$POSITIVOS_ASCII" | while IFS= read -r l; do center_text "$l"; done)
    WELCOME_MSG="Bem-vindo ao NGSOC - Suporte Técnico\nDiagnóstico, Recuperação e Reinstalação Segura."
    CENTERED_MSG=$(echo -e "$WELCOME_MSG" | while IFS= read -r l; do center_text "$l"; done)
    LINE=$(printf '=%.0s' $(seq 1 $WIDTH))
    FOOTER="© 2025 POSITIVOS+. Todos os direitos reservados."

    MSG="${CENTERED_ASCII}\n${CENTERED_POSITIVOS}\n${LINE}\n${CENTERED_MSG}\n${FOOTER}"
    set +e
    whiptail --title "NGSOC - Suporte" --msgbox "$MSG" $HEIGHT $WIDTH --ok-button "INICIAR"
    set -e
}

# -----------------------
# Menu principal
# -----------------------
main_menu() {
    while true; do
        set +e
        CHOICE=$(whiptail --title "NGSOC - Suporte" --menu "Escolha uma opção" $HEIGHT $WIDTH 8 \
            "1" "Diagnóstico" \
            "2" "Recuperação" \
            "3" "Reinstalação" \
            "0" "Sair" 3>&1 1>&2 2>&3)
        set -e

        case "$CHOICE" in
            1) diagnostico_menu ;;
            2) recuperacao_menu ;;
            3) reinstalacao_menu ;;
            0|"") clear; exit 0 ;;
        esac
    done
}

# -----------------------
# Diagnóstico (genérico e específico)
# -----------------------
diagnostico_menu() {
    while true; do
        set +e
        CHOICE=$(whiptail --title "Diagnóstico" --menu "Selecione o componente" 20 78 12 \
            "1" "Wazuh" \
            "2" "Harbor" \
            "3" "mitmproxy (cert export/ngsoc_exports)" \
            "4" "Trivy" \
            "5" "OpenVAS" \
            "6" "Metasploit" \
            "7" "ZAP" \
            "0" "Voltar" 3>&1 1>&2 2>&3)
        set -e

        case "$CHOICE" in
            1) diagnostico_wazuh ;;
            2) diagnostico_container "harbor" "/opt/ngsoc-deploy/docs/harbor/README.txt" "harbor|registry|harbor-log|harbor-core|registryctl|harbor-portal|nginx" ;;
            3) diagnostico_container "mitmproxy" "/opt/ngsoc-deploy/docs/mitmproxy/README.txt" "mitmproxy|ngsoc_mitmproxy|ngsoc_exports|nginx" ;;
            4) diagnostico_container "trivy" "/opt/ngsoc-deploy/docs/trivy/README.txt" "trivy|trivy-adapter" ;;
            5) diagnostico_container "openvas" "/opt/ngsoc-deploy/docs/openvas/README.txt" "openvas|greenbone|gvm" ;;
            6) diagnostico_container "metasploit" "/opt/ngsoc-deploy/docs/metasploit/README.txt" "metasploit|msf" ;;
            7) diagnostico_container "zap" "/opt/ngsoc-deploy/docs/zap/README.txt" "zap|zaproxy|ngsoc_zap" ;;
            0|"") break ;;
        esac
    done
}

diagnostico_container() {
    local NAME="$1"
    local README="$2"
    local PATTERN="$3"
    local LOG_DIR="/opt/ngsoc-deploy/logs/${NAME}"

    while true; do
        set +e
        CHOICE=$(whiptail --title "Diagnóstico - ${NAME}" --menu "Selecione uma ação" 20 78 10 \
            "1" "Readme" \
            "2" "Status Containers" \
            "3" "Check Logs (últimos 15 - host/container)" \
            "0" "Voltar" 3>&1 1>&2 2>&3)
        set -e

        case "$CHOICE" in
            1) show_file_if_exists "$README" "${NAME} - README" ;;
            2)
                TMP=$(mktemp)
                {
                    echo "Containers relacionados a ${NAME}:"
                    echo "================================"
                    containers_info_by_pattern "$PATTERN" || echo "(nenhum container encontrado)"
                } > "$TMP"
                whiptail --title "${NAME} - Status Containers" --scrolltext --textbox "$TMP" 20 80
                rm -f "$TMP"
                ;;
            3)
                TMP_LOG=$(mktemp)
                # primeiro tenta logs em host (/opt/ngsoc-deploy/logs/<comp>)
                logs=$(list_logs_sorted "$LOG_DIR" | tail -n 3)
                if [ -n "$logs" ]; then
                    {
                        echo "==== LOGS DO HOST: $LOG_DIR ===="
                        for f in $logs; do
                            echo ""
                            echo "----- ARQUIVO: $f -----"
                            tail -n 15 "$f" 2>/dev/null || echo "(erro lendo $f)"
                        done
                    } > "$TMP_LOG"
                else
                    # senão tenta docker logs dos containers que batem no pattern
                    conts=$(containers_names_by_pattern "$PATTERN")
                    if [ -n "$conts" ]; then
                        {
                            echo "==== LOGS DOS CONTAINERS (docker logs) ===="
                            for c in $conts; do
                                echo ""
                                echo "----- CONTAINER: $c -----"
                                docker logs --tail 15 "$c" 2>&1 | sed 's/^/ /' || echo "(erro docker logs $c)"
                            done
                        } > "$TMP_LOG"
                    else
                        echo "Nenhum log encontrado em $LOG_DIR e nenhum container correspondente a '$PATTERN'." > "$TMP_LOG"
                    fi
                fi

                # exibe no whip e grava no suporte.log
                whiptail --title "${NAME} - Últimos Logs" --scrolltext --textbox "$TMP_LOG" 25 90
                {
                    echo "[ $(date '+%Y-%m-%d %H:%M:%S') ] === CHECK LOGS: ${NAME} ==="
                    cat "$TMP_LOG"
                    echo ""
                } >> "$SUPORTE_LOG"
                rm -f "$TMP_LOG"
                ;;
            0|"") break ;;
        esac
    done
}

# -----------------------
# Diagnóstico Wazuh (específico)
# -----------------------
diagnostico_wazuh() {
    local README="/opt/ngsoc-deploy/docs/wazuh/README.txt"
    local LOG_DIR="/var/ossec/logs"
    local SERVICES=("wazuh-manager" "wazuh-indexer" "wazuh-dashboard")

    while true; do
        set +e
        CHOICE=$(whiptail --title "Diagnóstico - Wazuh" --menu "Selecione uma ação" 20 78 10 \
            "1" "Readme" \
            "2" "Status Service" \
            "3" "Check Logs (últimos 15)" \
            "0" "Voltar" 3>&1 1>&2 2>&3)
        set -e

        case "$CHOICE" in
            1) show_file_if_exists "$README" "Wazuh - README" ;;
            2)
                TMP=$(mktemp)
                {
                    echo "==== Status dos Serviços Wazuh ===="
                    for s in "${SERVICES[@]}"; do
                        if systemctl is-active --quiet "$s"; then
                            echo "✅ $s: ATIVO"
                        else
                            echo "❌ $s: INATIVO"
                        fi
                    done
                } > "$TMP"
                whiptail --title "Wazuh - Status Services" --scrolltext --textbox "$TMP" 20 80
                rm -f "$TMP"
                ;;
            3)
                TMP_LOG=$(mktemp)
                {
                    echo "==== Últimos logs do Wazuh ($LOG_DIR) ===="
                    for f in $(find "$LOG_DIR" -maxdepth 1 -type f -name '*.log' 2>/dev/null | sort | tail -n 3); do
                        echo ""
                        echo "----- ARQUIVO: $f -----"
                        tail -n 15 "$f" 2>/dev/null || echo "(erro lendo $f)"
                    done
                } > "$TMP_LOG"
                whiptail --title "Wazuh - Últimos Logs" --scrolltext --textbox "$TMP_LOG" 25 90
                {
                    echo "[ $(date '+%Y-%m-%d %H:%M:%S') ] === CHECK LOGS: Wazuh ==="
                    cat "$TMP_LOG"
                    echo ""
                } >> "$SUPORTE_LOG"
                rm -f "$TMP_LOG"
                ;;
            0|"") break ;;
        esac
    done
}

# -----------------------
# Recuperação (menu geral) - inclui Wazuh + containers
# -----------------------
recuperacao_menu() {
    while true; do
        set +e
        CHOICE=$(whiptail --title "Recuperação" --menu "Escolha o componente" 20 78 12 \
            "1" "Wazuh" \
            "2" "Harbor" \
            "3" "mitmproxy (+ ngsoc_exports/nginx)" \
            "4" "Trivy" \
            "5" "OpenVAS" \
            "6" "Metasploit" \
            "7" "ZAP" \
            "0" "Voltar" 3>&1 1>&2 2>&3)
        set -e

        case "$CHOICE" in
            1) recuperacao_wazuh ;;
            2) recuperacao_containers "Harbor" "harbor|registry|harbor-core|harbor-portal|harbor-jobservice|registryctl|harbor-log|nginx" "/opt/ngsoc-deploy/logs/harbor" ;;
            3) recuperacao_containers "mitmproxy" "mitmproxy|ngsoc_mitmproxy|ngsoc_exports|nginx" "/opt/ngsoc-deploy/logs/mitmproxy" ;;
            4) recuperacao_containers "Trivy" "trivy|trivy-adapter" "/opt/ngsoc-deploy/logs/trivy" ;;
            5) recuperacao_containers "OpenVAS" "openvas|greenbone|gvm" "/opt/ngsoc-deploy/logs/openvas" ;;
            6) recuperacao_containers "Metasploit" "metasploit|msf" "/opt/ngsoc-deploy/logs/metasploit" ;;
            7) recuperacao_containers "ZAP" "zap|zaproxy|ngsoc_zap" "/opt/ngsoc-deploy/logs/zap" ;;
            0|"") break ;;
        esac
    done
}

# recuperação Wazuh (mesmo padrão anterior, com gauge)
recuperacao_wazuh() {
    local SERVICES=("wazuh-manager" "wazuh-indexer" "wazuh-dashboard")
    while true; do
        CHOICE=$(whiptail --title "Recuperação - Wazuh" --menu "Selecione uma ação" 20 78 8 \
            "1" "Restart Services (com progresso)" \
            "2" "Status Services" \
            "3" "Logs de Ação (últimos 10)" \
            "0" "Voltar" 3>&1 1>&2 2>&3)
        case "$CHOICE" in
            1)
                # gauge reiniciando systemctl services
                {
                    pct=0
                    total=${#SERVICES[@]}
                    step=$((100 / total))
                    for s in "${SERVICES[@]}"; do
                        pct=$((pct + step)); [ "$pct" -gt 100 ] && pct=100
                        echo "$pct"; echo "XXX"; echo "$pct"; echo "Reiniciando $s..."; echo "XXX"
                        sudo systemctl restart "$s" 2>&1 || true
                        sleep 2
                    done
                    echo "100"; echo "XXX"; echo "100"; echo "Concluído"
                } | whiptail --gauge "Reiniciando serviços Wazuh..." 10 70 0

                TMP=$(mktemp)
                {
                    echo "==== Resultado do Restart Wazuh ===="
                    for s in "${SERVICES[@]}"; do
                        if systemctl is-active --quiet "$s"; then echo "✅ $s: ATIVO"; else echo "❌ $s: FALHA"; fi
                    done
                    echo "Finalizado: $(date '+%Y-%m-%d %H:%M:%S')"
                } > "$TMP"
                whiptail --title "Wazuh - Resultado Restart" --scrolltext --textbox "$TMP" 20 90
                {
                    echo "[ $(date '+%Y-%m-%d %H:%M:%S') ] === RECUPERAÇÃO WAZUH - Restart executado ==="
                    cat "$TMP"
                    echo ""
                } >> "$SUPORTE_LOG"
                rm -f "$TMP"
                ;;
            2)
                TMP=$(mktemp)
                {
                    echo "==== Status Serviços Wazuh ===="
                    for s in "${SERVICES[@]}"; do
                        if systemctl is-active --quiet "$s"; then echo "✅ $s: ATIVO"; else echo "❌ $s: INATIVO"; fi
                    done
                    echo "Verificado em: $(date '+%Y-%m-%d %H:%M:%S')"
                } > "$TMP"
                whiptail --title "Wazuh - Status Services" --scrolltext --textbox "$TMP" 20 90
                {
                    echo "[ $(date '+%Y-%m-%d %H:%M:%S') ] === RECUPERAÇÃO WAZUH - Status consultado ==="
                    cat "$TMP"
                    echo ""
                } >> "$SUPORTE_LOG"
                rm -f "$TMP"
                ;;
            3)
                TMP_LOG=$(mktemp)
                tail -n 10 "$SUPORTE_LOG" | grep -i "Wazuh" > "$TMP_LOG" || echo "Sem registros recentes de Wazuh." > "$TMP_LOG"
                whiptail --title "Wazuh - Logs de Ação (últimos 10)" --scrolltext --textbox "$TMP_LOG" 20 90
                rm -f "$TMP_LOG"
                ;;
            0|"") break ;;
        esac
    done
}

# recuperacao genérica para containers: detecta containers por pattern, reinicia com gauge, mostra status e grava log
recuperacao_containers() {
    local NAME="$1"
    local PATTERN="$2"
    local LOG_DIR="$3"

    # identifica containers existentes (nomes)
    conts=$(containers_names_by_pattern "$PATTERN")
    # passará a lista para a função de restart
    while true; do
        CHOICE=$(whiptail --title "Recuperação - ${NAME}" --menu "Selecione ação" 20 78 10 \
            "1" "Restart Containers (com progresso)" \
            "2" "Status Containers" \
            "3" "Logs de Ação (últimos 10)" \
            "0" "Voltar" 3>&1 1>&2 2>&3)
        case "$CHOICE" in
            1)
                # reinicia containers detectados
                if [ -n "$conts" ]; then
                    printf "%s\n" $conts | restart_containers_with_gauge
                else
                    # tenta pattern via docker ps (caso conts vazio)
                    conts2=$(docker ps -a --format "{{.Names}}" 2>/dev/null | grep -Ei "$PATTERN" || true)
                    printf "%s\n" $conts2 | restart_containers_with_gauge
                fi

                # após reiniciar, monta o status
                TMP=$(mktemp)
                {
                    echo "==== Status pós-Restart: ${NAME} ===="
                    docker ps -a --format "{{.Names}}\t{{.Status}}" 2>/dev/null | grep -Ei "$PATTERN" || echo "(nenhum container encontrado)"
                    echo "Finalizado em: $(date '+%Y-%m-%d %H:%M:%S')"
                } > "$TMP"
                whiptail --title "${NAME} - Status pós-Restart" --scrolltext --textbox "$TMP" 20 90

                {
                    echo "[ $(date '+%Y-%m-%d %H:%M:%S') ] === RECUPERAÇÃO ${NAME} - Restart executado ==="
                    cat "$TMP"
                    echo ""
                } >> "$SUPORTE_LOG"

                rm -f "$TMP"
                # atualiza conts
                conts=$(containers_names_by_pattern "$PATTERN")
                ;;
            2)
                TMP=$(mktemp)
                {
                    echo "==== Status Containers: ${NAME} ===="
                    docker ps -a --format "{{.Names}}\t{{.Status}}" 2>/dev/null | grep -Ei "$PATTERN" || echo "(nenhum container encontrado)"
                    echo "Verificado em: $(date '+%Y-%m-%d %H:%M:%S')"
                } > "$TMP"
                whiptail --title "${NAME} - Status Containers" --scrolltext --textbox "$TMP" 20 90
                {
                    echo "[ $(date '+%Y-%m-%d %H:%M:%S') ] === RECUPERAÇÃO ${NAME} - Status consultado ==="
                    cat "$TMP"
                    echo ""
                } >> "$SUPORTE_LOG"
                rm -f "$TMP"
                ;;
            3)
                TMP_LOG=$(mktemp)
                # tenta logs do host primeiro
                logs=$(list_logs_sorted "$LOG_DIR" | tail -n 3)
                if [ -n "$logs" ]; then
                    {
                        echo "==== LOGS DO HOST: $LOG_DIR ===="
                        for f in $logs; do
                            echo ""; echo "----- ARQUIVO: $f -----"; tail -n 15 "$f" 2>/dev/null || echo "(erro lendo $f)"
                        done
                    } > "$TMP_LOG"
                else
                    # docker logs dos containers detectados
                    conts_now=$(docker ps -a --format "{{.Names}}" 2>/dev/null | grep -Ei "$PATTERN" || true)
                    if [ -n "$conts_now" ]; then
                        {
                            echo "==== LOGS DOS CONTAINERS (docker logs) ===="
                            for c in $conts_now; do
                                echo ""; echo "----- CONTAINER: $c -----"; docker logs --tail 15 "$c" 2>&1 | sed 's/^/ /' || echo "(erro docker logs $c)"
                            done
                        } > "$TMP_LOG"
                    else
                        echo "Nenhum log encontrado em $LOG_DIR e nenhum container correspondente a '$PATTERN' para docker logs." > "$TMP_LOG"
                    fi
                fi

                whiptail --title "${NAME} - Logs de Ação" --scrolltext --textbox "$TMP_LOG" 25 90
                {
                    echo "[ $(date '+%Y-%m-%d %H:%M:%S') ] === RECUPERAÇÃO ${NAME} - CHECK LOGS ==="
                    cat "$TMP_LOG"
                    echo ""
                } >> "$SUPORTE_LOG"
                rm -f "$TMP_LOG"
                ;;
            0|"") break ;;
        esac
    done
}

# -----------------------
# Reinstalação placeholder
# -----------------------
reinstalacao_menu() {
    whiptail --msgbox "Módulo de Reinstalação em construção. Será implementado por componente com passos seguros." 8 60
}

# -----------------------
# Execução
# -----------------------
show_welcome
main_menu
