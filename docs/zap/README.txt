==========================================================
NG-SOC - OWASP ZAP (Zed Attack Proxy) v2.14.0
==========================================================

🌐 PORTAL WEB / INTERFACE

- URL: http://192.168.100.23:8080
- Interface: API HTTP (modo daemon)
- O container executa a API aberta para integração.

📦 CONTAINER

| Serviço | Imagem | Porta | Função |
| :--- | :--- | :--- | :--- |
| **ngsoc_zap** | ghcr.io/zaproxy/zaproxy:2.14.0 | 8080 | Proxy e motor de varredura HTTP/HTTPS |

📁 ESTRUTURA DE DIRETÓRIOS

- /opt/ngsoc-deploy/data/zap/home  : persistência do ZAP (.ZAP)
- /opt/ngsoc-deploy/logs/zap       : logs do container (via rsyslog)
- /opt/ngsoc-deploy/reports/zap    : relatórios exportados (SARIF/JSON/HTML)
- /opt/ngsoc-deploy/docs/zap       : documentação do componente
- /opt/ngsoc-deploy/exports/zap    : artefatos/exports (se aplicável)

🧠 DETALHES TÉCNICOS

- Porta API padrão:  8080
- API key: desativada (--config api.disablekey=true)
- Origens: permitido (api.addrs.addr.regex=true)

🐳 OPERAÇÕES COM DOCKER (Resumido)

- Ver status:
  docker ps | grep ngsoc_zap
- Logs em tempo real:
  docker logs -f ngsoc_zap
- Reiniciar:
  docker restart ngsoc_zap
- Parar:
  docker stop ngsoc_zap

🔧 TROUBLESHOOTING RÁPIDO

1. Teste API local:
   curl http://127.0.0.1:8080/JSON/core/view/version/
2. Conferir logs:
   tail -f /opt/ngsoc-deploy/logs/zap/zap.log
3. Se não subir:
   - verificar Docker ativo (systemctl status docker)
   - permissões em /opt/ngsoc-deploy/data/zap/home

⚠️ NOTAS

- Container roda em modo daemon sem GUI nativa. Use zap-cli / APIs para operar.
- Relatórios: /opt/ngsoc-deploy/reports/zap/
- Ajuste IP/porta em caso de instalação em outro servidor.

📚 REFERÊNCIAS
- https://www.zaproxy.org
- https://www.zaproxy.org/docs/api/
