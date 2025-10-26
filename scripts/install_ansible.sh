
#!/bin/bash
echo "================================================="
echo "🤖 INÍCIO: Instalação do Ansible (Orquestrador)..."
echo "================================================="
sudo add-apt-repository --yes --update ppa:ansible/ansible || { echo "❌ ERRO: Falha ao adicionar PPA do Ansible."; exit 1; }
sudo apt install -y -q ansible || { echo "❌ ERRO: Falha na instalação do Ansible."; exit 1; }

echo "VERSÃO: $(ansible --version | head -n 1)"
echo "✅ Ansible instalado com sucesso."

