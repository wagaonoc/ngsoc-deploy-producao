==========================================================
NG-SOC - Harbor Registry Usage & Access (vv2.14.0)
==========================================================

🌐 ACESSO AO PORTAL WEB:

* HTTPS: harbor.local:8443 (Recomendado)
* HTTP: harbor.local:8081

* Para acessar a partir de outra máquina, o hostname 'harbor.local'
  deve ser mapeado para o IP '192.168.100.23'
  no arquivo /etc/hosts (ou DNS).

🔒 CREDENCIAIS ADMINISTRATIVAS:

* Usuário: admin
* Senha: Harbor12345

🐳 SERVIÇOS HARBOR (Containers):

O Harbor é composto por diversos containers para garantir todas as suas funcionalidades. 
Eles são controlados pelo docker-compose.yml em /opt/ngsoc-deploy/data/harbor/installer.

| Serviço (Compose) | Container Imagem | Função Primária |
| :--- | :--- | :--- |
| **nginx** | goharbor/nginx-photon | Proxy reverso, SSL e Exposição de portas (8443/8081). |
| **harbor-core** | goharbor/harbor-core | API central, autenticação e gerenciamento de projetos. |
| **harbor-portal** | goharbor/harbor-portal | Interface Web (UI) do usuário. |
| **registry** | goharbor/registry-photon | Armazenamento real das imagens (Docker Distribution). |
| **registryctl** | goharbor/harbor-registryctl | Controlador do Registry, gerencia eventos e metadados. |
| **harbor-db** | goharbor/harbor-db | Banco de dados PostgreSQL (metadados e configurações). |
| **redis** | goharbor/redis-photon | Cache e gerenciamento de sessões/estado. |
| **harbor-jobservice** | goharbor/harbor-jobservice | Gerenciamento de tarefas assíncronas (GC, replicações, scanners). |
| **trivy-adapter** | goharbor/trivy-adapter-photon | Adaptação e execução do scanner de vulnerabilidades Trivy. |
| **harbor-log** | goharbor/harbor-log | Coleta e agrega logs de todos os outros serviços. |

🔧 COMANDOS BÁSICOS (Troubleshooting):

* Status dos containers:
  cd /opt/ngsoc-deploy/data/harbor/installer && docker compose ps
* Logs em tempo real (exemplo: Core Service):
  docker logs -f harbor-core
* Parar todos os serviços:
  cd /opt/ngsoc-deploy/data/harbor/installer && docker compose down
* Limpeza completa (CUIDADO - remove dados):
  cd /opt/ngsoc-deploy/data/harbor/installer && ./uninstall.sh
  
⚠️ NOTAS CRÍTICAS DE IMPLANTAÇÃO:

1. Conflito 1514 RESOLVIDO: A porta 1514 (Syslog) foi desativada no Harbor para evitar
   conflito com o Wazuh. Os logs devem ser coletados via **arquivo** pelo Wazuh Agent.
   Caminho do Log Central: **/opt/ngsoc-deploy/logs/harbor/core.log**
   
2. Certificado SSL: Está utilizando um certificado SSL autoassinado ('nginx-selfsigned.crt').
   O cliente Docker deve confiar neste certificado antes de qualquer login ou push/pull.
   (O script do Ansible já fez a configuração local no /etc/hosts.)
   
