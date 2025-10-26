#!/usr/bin/env bash
# ==========================================================
# 🚀 NGSOC - Push Backup Automático para GitHub (v5 - Revisado)
# ==========================================================
# Envia scripts, playbooks, docs e configs essenciais.
# Usa autenticação com token GitHub (pode ser definido via variável).
# ==========================================================

set -euo pipefail

# ===== CONFIGURAÇÕES =====
REPO_URL="https://github.com/wagaonoc/ngsoc-deploy-producao.git"
BRANCH="main"
GIT_USER="wagaonoc"

# ⚙️ Token do GitHub (adicione manualmente se quiser evitar prompt)
GIT_TOKEN="${GIT_TOKEN:-}"

BACKUP_ROOT="/opt/ngsoc-deploy"
TIMESTAMP="$(date '+%Y-%m-%d %H:%M:%S')"

msg() { echo -e "\033[1;34m$1\033[0m"; }
err() { echo -e "\033[1;31m$1\033[0m" >&2; }

msg "=========================================================="
msg "📦 INICIANDO BACKUP GIT DO NGSOC (${TIMESTAMP})"
msg "=========================================================="

cd "$BACKUP_ROOT"

# ==========================================================
# 🧩 Inicialização Git + .gitignore
# ==========================================================
if [ ! -d ".git" ]; then
    msg "🧩 Inicializando repositório Git..."
    git init
    git branch -M "$BRANCH"
    git remote add origin "$REPO_URL" || true
fi

cat <<'EOF' > "${BACKUP_ROOT}/.gitignore"
# ===== IGNORAR DADOS OPERACIONAIS =====
data/*
!data/harbor/
!data/harbor/installer/
!data/harbor/installer/common/
!data/harbor/installer/common/config/
!data/harbor/installer/common/config/jobservice/
!data/openvas/
!data/openvas/greenbone/
logs/
reports/
exports/
*.log
*.bak
*.tmp
*.tar
*.gz
*.zip
*.rdb
*.db
*.sqlite
*.sock
*.pid
*.swp
__pycache__/
*.pyc
*.class
EOF

# ==========================================================
# 📁 Diretórios que serão enviados
# ==========================================================
INCLUDE_DIRS=(
    "scripts"
    "Ansible"
    "docs"
    "data/harbor/installer"
    "data/harbor/installer/common/config/jobservice"
    "data/openvas/greenbone"
)

msg "📦 INCLUINDO DIRETÓRIOS NO BACKUP:"
for dir in "${INCLUDE_DIRS[@]}"; do
    if [ -d "$dir" ]; then
        msg "   ✅ $dir"
        git add -f "$dir"
    else
        msg "   ⚠️ Diretório ausente: $dir"
    fi
done

# ==========================================================
# ⚙️ Cópia de configs externas (Rsyslog + Wazuh)
# ==========================================================
mkdir -p external-configs
copy_safe() {
  SRC="$1"; DEST="$2"
  if [ -d "$SRC" ]; then
    msg "📁 Copiando $SRC → $DEST"
    sudo rsync -a --delete "$SRC/" "$DEST/"
  else
    msg "⚠️ Diretório não encontrado: $SRC"
  fi
}
copy_safe "/etc/rsyslog.d" "external-configs/rsyslog"
copy_safe "/var/ossec/etc" "external-configs/wazuh-etc"
copy_safe "/var/ossec/integrations" "external-configs/wazuh-integrations"

git add external-configs || true

# ==========================================================
# 📝 Commit datado
# ==========================================================
msg "📝 Criando commit..."
git commit -m "Backup automático NGSOC - ${TIMESTAMP}" || msg "ℹ️ Nenhuma alteração nova."

# ==========================================================
# 🔐 Configurar autenticação GitHub
# ==========================================================
if [ -z "$GIT_TOKEN" ]; then
  read -rp "🔑 Cole seu GitHub PAT Token (github_pat_...): " GIT_TOKEN
fi
git remote set-url origin "https://${GIT_USER}:${GIT_TOKEN}@github.com/wagaonoc/ngsoc-deploy-producao.git"

# ==========================================================
# 🚀 Enviar alterações
# ==========================================================
msg "📤 Enviando alterações para o repositório remoto..."
if git push -u origin "$BRANCH"; then
    msg "✅ Backup enviado com sucesso!"
else
    err "❌ Falha no push. Verifique o token ou permissões do repositório."
    exit 1
fi

msg "=========================================================="
msg "🎯 BACKUP FINALIZADO COM SUCESSO (${TIMESTAMP})"
msg "=========================================================="
