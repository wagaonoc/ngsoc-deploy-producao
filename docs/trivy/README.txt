==========================================================
NGSOC - Trivy Vulnerability Scanner (RPC Mode)
==========================================================
Container: trivy-server
Image    : aquasec/trivy:0.54.1
Mode     : Server RPC
Port     : 4954
Network  : ngsoc_net
----------------------------------------------------------
Paths:
- Cache   : /opt/ngsoc-deploy/data/trivy
- Logs    : /opt/ngsoc-deploy/logs/trivy
- Reports : /opt/ngsoc-deploy/reports/trivy
----------------------------------------------------------
Test:
curl http://localhost:4954/health
==========================================================
