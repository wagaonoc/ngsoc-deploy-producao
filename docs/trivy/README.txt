==========================================================
NG-SOC - Trivy Usage & Access
==========================================================
Container       : ngsoc_trivy
Mode            : server (RPC, não GUI)
Image           : aquasec/trivy:0.44.1
Data dir        : /opt/ngsoc-deploy/data/trivy
Logs dir        : /opt/ngsoc-deploy/logs/trivy
Reports dir     : /opt/ngsoc-deploy/reports/trivy
Proxy config    : /opt/ngsoc-deploy/data/trivy-proxy/nginx-conf
Proxy auth      : /opt/ngsoc-deploy/data/trivy-proxy/nginx-auth
Server API Port : 4954
Access Point    : http://<IP_DO_SERVIDOR>:4954 (API/RPC)
Basic Auth      : trivy/trivy (Ativo se Nginx Proxy for implantado)

Modo de uso do Trivy:
- CLI mode:
  docker exec -it ngsoc_trivy trivy <options>

- Server mode (RPC, não GUI):
  Utilize o Trivy client para se conectar ao servidor:
  docker exec -it ngsoc_trivy sh -c "TRIVY_SERVER='http://localhost:4954' trivy image alpine:latest"

Nota:
- Server mode é RPC: **não há interface web**, apenas acesso via client.
- Certifique-se de mapear corretamente a porta 4954.
- Logs e reports são persistidos nos diretórios listados acima.
- Para atualizar o DB de vulnerabilidades (CLI mode):
  docker exec -it ngsoc_trivy trivy image --download-db-only
