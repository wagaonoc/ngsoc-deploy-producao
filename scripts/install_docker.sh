#!/bin/bash
set -e

echo "================================================="
echo "🐳 INÍCIO: Instalação de Docker e Docker Compose (NGSOC)"
echo "================================================="

# --- Remover versões antigas (caso exista resquício) ---
sudo apt remove -y docker docker-engine docker.io containerd runc || true

# --- Dependências ---
sudo apt update -q
sudo apt install -y -q ca-certificates curl gnupg lsb-release apt-transport-https software-properties-common

# --- Repositório oficial Docker ---
sudo install -m 0755 -d /etc/apt/keyrings
if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
fi

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
  https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
  | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

# --- Instalação ---
sudo apt update -q
sudo apt install -y -q \
  docker-ce docker-ce-cli containerd.io \
  docker-buildx-plugin docker-compose-plugin

# --- Habilitar e iniciar ---
sudo systemctl enable docker
sudo systemctl start docker

# --- Permitir uso sem sudo (caso execute manualmente os deploys) ---
if ! getent group docker >/dev/null; then
    sudo groupadd docker
fi
sudo usermod -aG docker "$USER" || true

# --- Teste de verificação ---
echo "-------------------------------------------------"
docker --version
docker compose version || echo "⚠️ Docker Compose plugin não detectado."
echo "-------------------------------------------------"
echo "✅ Docker e Compose instalados com sucesso."
echo "✅ Adicionado usuário ao grupo docker (logout necessário)."
echo "================================================="
