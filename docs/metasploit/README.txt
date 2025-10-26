==========================================================
NG-SOC - Metasploit Deployment
==========================================================
Container (DB)    : msf-db
Container (MSF)   : metasploit
Postgres image    : postgres:15-alpine
Metasploit image  : metasploitframework/metasploit-framework:latest

Data dir (postgres): /opt/ngsoc-deploy/data/metasploit/pg_data
MSF data (.msf4)   : /opt/ngsoc-deploy/data/metasploit/msf_data
Logs dir           : /opt/ngsoc-deploy/logs/metasploit

DB user: msfuser
DB name: msfdb

Observações:
- As credenciais completas foram gravadas em: /opt/ngsoc-deploy/docs/metasploit/credentials.txt (modo 0600, root:root).
- Recomendamos mover essas credenciais para um cofre seguro (ansible-vault, HashiCorp Vault, Azure Key Vault) e remover o arquivo plaintext quando apropriado.

Principais comandos:
- Acessar msfconsole:
  docker exec -it metasploit msfconsole
- Checar containers:
  docker ps
- Ver logs do Metasploit:
  docker logs metasploit --follow

Generated: 2025-10-02T16:35:02+00:00
