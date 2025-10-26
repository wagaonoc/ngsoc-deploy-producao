#!/bin/bash
set -e

echo "================================================="
echo "🤖 INÍCIO: Instalação do Ansible (Orquestrador NGSOC)"
echo "================================================="

# --- Atualização e dependências ---
sudo apt update -q
sudo apt install -y -q software-properties-common curl python3 python3-pip

# --- Adicionar repositório oficial ---
if ! grep -q "ansible/ansible" /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null; then
    sudo add-apt-repository --yes --update ppa:ansible/ansible
fi

# --- Instalação do Ansible ---
sudo apt install -y -q ansible

# --- Verificação de versão ---
echo "-------------------------------------------------"
ansible --version | head -n 3
echo "-------------------------------------------------"

# --- Ajustes de compatibilidade (caso use pip em playbooks) ---
pip install --upgrade ansible-core ansible-lint jmespath || true

echo "✅ Ansible instalado e pronto para uso com playbooks NGSOC."
echo "================================================="
