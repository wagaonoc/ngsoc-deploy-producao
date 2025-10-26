#!/bin/bash
set -e

echo "================================================="
echo "⚙️ INÍCIO: Instalação e Configuração de Ferramentas Básicas (NGSOC)"
echo "================================================="

# --- Atualização geral ---
sudo apt update -q && sudo apt upgrade -y -q

# --- Ferramentas essenciais ---
sudo apt install -y -q \
  git \
  curl \
  wget \
  vim \
  nano \
  htop \
  net-tools \
  traceroute \
  nmap \
  iproute2 \
  software-properties-common \
  apt-transport-https \
  ca-certificates \
  gnupg \
  lsb-release \
  unzip \
  tar \
  rsync \
  jq \
  python3 \
  python3-pip \
  gnupg-agent \
  build-essential \
  ufw \
  bash-completion \
  tree

echo "✅ Pacotes básicos instalados."

# --- Ferramentas de rede e monitoramento ---
sudo apt install -y -q \
  tcpdump \
  iputils-ping \
  dnsutils \
  netcat-openbsd \
  whois \
  iftop \
  iotop

echo "✅ Ferramentas de rede instaladas."

# --- Ferramentas úteis para containers / automação ---
sudo apt install -y -q \
  ansible \
  make \
  cron \
  dos2unix \
  pv \
  gpg

echo "✅ Ferramentas DevOps e automação instaladas."

# --- Git (sem credenciais pessoais) ---
git config --system pull.rebase false
git config --system core.compression 9
git config --system gc.auto 0
echo "✅ Git instalado e otimizado."

# --- Fix de locale / UTF-8 ---
sudo apt install -y -q locales
sudo locale-gen en_US.UTF-8
sudo update-locale LANG=en_US.UTF-8

# --- Utilitários de sistema e troubleshooting ---
sudo apt install -y -q \
  sysstat \
  lsof \
  psmisc \
  iptables \
  nfs-common \
  libssl-dev

# --- Ferramentas de log e busca ---
sudo apt install -y -q \
  logrotate \
  silversearcher-ag \
  ripgrep

# --- Instalação de Git Filter Repo (para manutenção de repositórios grandes) ---
pip install --upgrade git-filter-repo || true
echo "✅ Git Filter Repo disponível para limpeza de histórico pesado."

# --- Limpeza e otimização final ---
sudo apt autoremove -y -q
sudo apt clean -q

echo "================================================="
echo "🎯 INSTALAÇÃO BÁSICA CONCLUÍDA COM SUCESSO!"
echo "================================================="
