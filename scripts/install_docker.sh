
#!/bin/bash
echo "================================================="
echo "🐳 INÍCIO: Instalação de Docker e Docker Compose..."
echo "================================================="
# Configuração de chaves e repositório
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt update -q
sudo apt install -y -q docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin || { echo "❌ ERRO: Falha na instalação do Docker."; exit 1; }

sudo systemctl start docker
sudo systemctl enable docker
echo "✅ Docker e Compose instalados e serviço iniciado."

