==========================================================
NG-SOC - MITMProxy Usage & Access (ngsoc_mitmproxy)
==========================================================

🌐 ACESSO AO UI (Mitmweb):
* URL: http://192.168.100.23:8090/#/flows

🔧 ACESSO AO PROXY:
* Host: 192.168.100.23
* Porta: 8089

📁 DIRETÓRIOS PERSISTENTES:
* Data:    /opt/ngsoc-deploy/data/mitmproxy
* Certs:   /opt/ngsoc-deploy/data/mitmproxy/certs
* Logs:    /opt/ngsoc-deploy/logs/mitmproxy
* Exports: /opt/ngsoc-deploy/exports/mitmproxy
* Reports: /opt/ngsoc-deploy/reports/mitmproxy
* Docs:    /opt/ngsoc-deploy/docs/mitmproxy

🔐 CERTIFICADO/CA:
* Export público: /opt/ngsoc-deploy/exports/mitmproxy/mitmproxy-ca-cert.pem
* Backup interno: /opt/ngsoc-deploy/data/mitmproxy/certs/mitmproxy-ca-cert.pem

🧩 CONTAINER:
* Nome: ngsoc_mitmproxy
* Imagem: mitmproxy/mitmproxy:latest
* Reinício automático: always
* Volume: /opt/ngsoc-deploy/logs/mitmproxy:/home/mitmproxy/.mitmproxy

🧰 COMANDOS ÚTEIS:
* docker ps --filter "name=ngsoc_mitmproxy"
* tail -f /opt/ngsoc-deploy/logs/mitmproxy/mitmproxy.log
* docker cp ngsoc_mitmproxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem /opt/ngsoc-deploy/exports/mitmproxy/
