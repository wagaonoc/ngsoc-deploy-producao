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
  python3-venv \
  python3-dev \
  gnupg-agent \
  build-essential \
  tree \
  openssl

echo "✅ Pacotes básicos instalados."

# --- Segurança e auditoria ---
sudo apt install -y -q \
  ufw \
  fail2ban \
  auditd \
  policycoreutils

echo "✅ Hardening básico instalado."

# --- Ferramentas DevOps / automação ---
sudo apt install -y -q \
  ansible \
  make \
  cron \
  dos2unix \
  pv

echo "✅ Ferramentas DevOps instaladas."

# --- SSH server (se ausente) ---
if ! dpkg -l | grep -q openssh-server; then
  sudo apt install -y openssh-server
  sudo systemctl enable ssh
  sudo systemctl start ssh
  echo "✅ SSH habilitado."
fi

# --- Fix de locale / UTF-8 ---
sudo apt install -y locales
sudo locale-gen en_US.UTF-8
sudo update-locale LANG=en_US.UTF-8

# --- Limpeza ---
sudo apt autoremove -y -q
sudo apt clean -q

echo "================================================="
echo "🎯 INSTALAÇÃO BÁSICA CONCLUÍDA COM SUCESSO!"
echo "================================================="
