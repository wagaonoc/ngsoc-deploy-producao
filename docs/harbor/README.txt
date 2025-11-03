==========================================================
NG-SOC - Harbor Registry (v2.14.0)
==========================================================
Web:
  HTTPS: harbor.local:8443
  HTTP : harbor.local:8081

Admin:
  user: admin
  pass: Harbor12345

Diretórios:
  Installer : /opt/ngsoc-deploy/data/harbor/installer
  Data      : /opt/ngsoc-deploy/data/harbor/data
  Logs      : /opt/ngsoc-deploy/logs/harbor

Notas:
  - Syslog(1514) desativado (port=0).
  - Logs locais em /opt/ngsoc-deploy/logs/harbor.
  - Trivy externo: habilitado em ngsoc_net.
