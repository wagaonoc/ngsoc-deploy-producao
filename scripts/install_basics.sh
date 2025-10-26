
#!/bin/bash
echo "================================================="
echo "⚙️ INÍCIO: Instalação de Ferramentas Básicas..."
echo "================================================="
sudo apt update -q
sudo apt install -y -q git curl wget net-tools software-properties-common lsb-release || { echo "❌ ERRO: Falha na instalação de pacotes básicos."; exit 1; }
echo "✅ Ferramentas básicas instaladas com sucesso."

