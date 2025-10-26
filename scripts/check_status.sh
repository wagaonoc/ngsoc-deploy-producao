
#!/bin/bash
echo "==================================================="
echo "🔎 Verificando STATUS DOS SERVIÇOS NGSOC"
echo "==================================================="
echo "--- STATUS DOCKER CONTÊINERES (Container Name, Status, Ports) ---"
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"

echo -e "\n--- STATUS WAZUH MANAGER ---"
if command -v systemctl &> /dev/null; then
    sudo systemctl status wazuh-manager 2>/dev/null | grep Active || echo "Wazuh Manager: Não Instalado ou Inativo"
else
    echo "Não é possível verificar o status do serviço."
fi
echo "==================================================="

