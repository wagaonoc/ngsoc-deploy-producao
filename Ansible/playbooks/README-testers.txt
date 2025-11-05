NG-SOC - MITMProxy Test & Deployment Checklist
---------------------------------------------

1) Comando de deploy
   ./install_mitmproxy_docker.sh

2) URLs / Acesso
   - Mitmweb UI: http://<HOST_IP>:8090  (ex: http://192.168.100.23:8090)
   - Proxy (HTTP/HTTPS): <HOST_IP>:8089  (ex: 192.168.100.23:8089)
   - CA export (nginx export): http://<HOST_IP>:8085/mitmproxy-ca-cert.pem

3) Validações imediatas (após deploy)
   - Confirmar container:
       docker ps --filter "name=ngsoc_mitmproxy"
   - Confirmar CA disponível:
       curl -sS http://127.0.0.1:8085/mitmproxy-ca-cert.pem -o /tmp/mitmproxy-ca.pem
       openssl x509 -in /tmp/mitmproxy-ca.pem -noout -subject -issuer -dates
   - Teste HTTPS via proxy (usa CA):
       curl --cacert /tmp/mitmproxy-ca.pem -x http://<HOST_IP>:8089 -I https://www.example.com

4) Persistência / Reinício
   - Certifique-se que os certificados ficam em:
       /opt/ngsoc-deploy/exports/mitmproxy/mitmproxy-ca-cert.pem
       /opt/ngsoc-deploy/data/mitmproxy/certs/mitmproxy-ca-cert.pem
   - Teste de recriação do container:
       sha256sum /opt/ngsoc-deploy/exports/mitmproxy/mitmproxy-ca-cert.pem
       docker rm -f ngsoc_mitmproxy
       ./install_mitmproxy_docker.sh
       sha256sum /opt/ngsoc-deploy/exports/mitmproxy/mitmproxy-ca-cert.pem
     -> Checksums devem ser idênticos

5) Logs / Troubleshooting
   - Logs locais do container: /opt/ngsoc-deploy/logs/mitmproxy/*.log
   - Visualizar logs do container:
       docker logs --tail 200 ngsoc_mitmproxy
   - Em caso de erro de "port already allocated": verificar containers que usam 8089/8090 e remover duplicatas

6) Segurança
   - Não comitar segredo em texto plano. Use Ansible Vault para mitm_ui_pass.
   - Restrinja acesso ao UI via firewall/ACLs se exposto a redes não confiáveis.
   - Proteja o CA: armazene cópias em local seguro.

7) Contato / Notas
   - Playbook: Ansible/playbooks/deploy_mitmproxy.yml
   - Script de instalação: scripts/install_mitmproxy_docker.sh
   - Diretórios persistidos: /opt/ngsoc-deploy/{data,logs,exports}/mitmproxy
