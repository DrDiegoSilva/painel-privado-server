# painel-privado-server

Pequeno serviço que serve um painel HTML semanal **somente depois do login**. A senha é conferida no servidor, com limite de tentativas; o arquivo do painel nunca é entregue a quem não está logado. Este repositório tem só o código: nenhuma senha, hash, token ou dado.

## Como funciona
- **Senha:** só o hash bcrypt (custo 12), na variável `PASSWORD_HASH_B64` (o hash em base64, para não ter `$`).
- **Limites de tentativa:**
  - Por IP: 5 erros em 15 min bloqueiam o IP por 15 min.
  - Global: mais de 20 erros na última hora bloqueiam o login para todos por 15 min, dobrando a cada novo bloqueio em 24 h, até 24 h.
  - Quem já tem sessão continua entrando durante os bloqueios.
  - O estado fica em `DATA_DIR/state.json` e sobrevive a reinício.
- **Log:** `DATA_DIR/logs/auth.log` (JSON por linha) registra `login_ok`, `login_fail`, `login_blocked`, `token_fail` e `publish`. A senha nunca é registrada.
- **Sessão:** cookie `__Host-painel_sess` com HttpOnly, Secure e SameSite=Lax, válido por 90 dias (`SESSION_DAYS`), assinado com HMAC-SHA256. O segredo é gerado no 1º boot em `DATA_DIR/session_secret`; apagar esse arquivo derruba todas as sessões. Um link **"sair"** é injetado no painel.
- **HTTPS e cabeçalhos:**
  - Exige `X-Forwarded-Proto: https`, enviado pelo proxy reverso; sem ele, a requisição recebe 308 para https.
  - Cabeçalhos: HSTS, `X-Robots-Tag: noindex`, `robots.txt` Disallow, `Cache-Control: no-store`, `X-Frame-Options: DENY`, `Referrer-Policy: no-referrer`.
- **Rotas:**
  - Livres: `/login`, `/logout`, `/healthz`, `/robots.txt`, `/assets/logo.png`.
  - Com sessão: `/` (painel mais recente), `/h/` (histórico), `/h/AAAA-MM-DD`.
- **Publicação:**
  - `PUT /api/dashboards/AAAA-MM-DD` com `Authorization: Bearer <token>` e o HTML no corpo (até 20 MB).
  - `GET /api/status` devolve a data mais recente e o sha256.
  - O servidor guarda só o sha256 do token (`PUBLISH_TOKEN_SHA256`).

## Variáveis de ambiente
| Variável | Obrigatória | Descrição |
|---|---|---|
| `PASSWORD_HASH_B64` | sim | `printf '%s' "$SENHA" \| node hash-password.js --b64` |
| `PUBLISH_TOKEN_SHA256` | sim | sha256 (hex) do token de publicação |
| `SESSION_DAYS` | não | padrão 90 |
| `TRUST_PROXY` | não | padrão 1 (um proxy reverso na frente) |
| `DATA_DIR` / `PORT` | não | padrão `/data` / `80` |

Volume persistente **obrigatório** em `/data`. O container escuta na porta **80** como usuário não-root.

## Implantação (Easypanel)
1. **+ Service → App**.
2. **Source → Git**: este repositório, branch `main`, build **Dockerfile**.
3. **Environment**: `PASSWORD_HASH_B64` e `PUBLISH_TOKEN_SHA256`.
4. **Mounts → Add Volume**: caminho `/data`.
5. **Domains**: o domínio padrão do Easypanel ou um próprio, porta **80**.
6. **Deploy**.

## Publicar uma versão
```bash
printf 'Authorization: Bearer %s\n' "$(cat token.txt)" | \
  curl -sS -H @- -X PUT --data-binary @painel.html https://SEU-DOMINIO/api/dashboards/2026-10-16
```

## Teste local
```bash
npm ci
TEST_PASSWORD=... ENV_FILE=caminho/do/env TOKEN_FILE=caminho/do/token ./test_local.sh
```
O teste cobre: nada servido sem login, upload com token, senha certa e errada, bloqueio por IP e global, persistência, cookie, sair, e HTTPS/HSTS em modo produção. `ALLOW_HTTP=1` serve só para teste local.

## Limites conhecidos
- Com senha curta, a segurança vem do limite de tentativas no servidor. Proteja o acesso às variáveis de ambiente: o hash vazado permite tentar a senha offline.
- Um atacante pode provocar o bloqueio global e impedir **novos** logins por um tempo. Sessões existentes não são afetadas.
- Atrás de dois proxies (por exemplo, Cloudflare com proxy na frente do Traefik), use `TRUST_PROXY=2`.
