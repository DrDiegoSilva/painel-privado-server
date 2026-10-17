#!/usr/bin/env bash
# Teste local do painel-privado (sem Docker): sobe o servidor em 127.0.0.1, roda os cenários e derruba.
# Variáveis: TEST_PASSWORD (senha), ENV_FILE (linhas PASSWORD_HASH_B64=... e PUBLISH_TOKEN_SHA256=...), TOKEN_FILE (token em claro),
#            TEST_HTML (opcional; padrão = HTML sintético), PUBLISH_SCRIPT (opcional; publicador do box a testar também).
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ENV_FILE="${ENV_FILE:?defina ENV_FILE}"; TOKEN_FILE="${TOKEN_FILE:?defina TOKEN_FILE}"
PW="${TEST_PASSWORD:?defina TEST_PASSWORD}"     # a senha só existe na variável deste processo
D="$(mktemp -d)"; P=18765
HTML="${TEST_HTML:-$D/teste.html}"; [[ -n "${TEST_HTML:-}" ]] || printf '<!doctype html><html><body><div class="sub">x</div><p>conteudo-protegido-de-teste</p></body></html>' > "$HTML"
TAG=2026-10-16; B="http://127.0.0.1:$P"; pass=0; fail=0
ok(){ if eval "$2"; then echo "  ok   $1"; pass=$((pass+1)); else echo "  FALHA $1"; fail=$((fail+1)); fi; }
start(){ ( while IFS= read -r l; do [[ -n "$l" ]] && export "$l"; done < "$ENV_FILE"; DATA_DIR="$D" PORT=$P "$@" node "$HERE/server.js" >"$D/server.log" 2>&1 & echo $! >"$D/pid" ); sleep 0.8; }
stop(){ kill "$(cat "$D/pid")" 2>/dev/null; sleep 0.5; }
login(){ curl -s -o /dev/null -D - -H "X-Forwarded-For: $1" --data-urlencode "password=$2" "$B/login" "${@:3}"; }

echo "== modo teste (ALLOW_HTTP=1)"; start env ALLOW_HTTP=1
r=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' "$B/"); ok "sem login, / -> 303 /login ($r)" '[[ "$r" == "303 $B/login" ]]'
r=$(curl -s -o /dev/null -w '%{http_code}' "$B/h/2026-10-16"); ok "sem login, /h/2026-10-16 -> 303 ($r)" '[[ "$r" == 303 ]]'
r=$(curl -s -o /dev/null -w '%{http_code}' "$B/api/status"); ok "API sem token -> 401 ($r)" '[[ "$r" == 401 ]]'
r=$(curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer errado' -X PUT --data-binary @"$HTML" "$B/api/dashboards/2026-10-16"); ok "upload com token errado -> 401 ($r)" '[[ "$r" == 401 ]]'
up=$(printf 'Authorization: Bearer %s\n' "$(cat "$TOKEN_FILE")" | curl -s -H @- -X PUT --data-binary @"$HTML" "$B/api/dashboards/2026-10-16")
ok "upload com token certo -> sha igual" '[[ "$(jq -r .sha256 <<<"$up")" == "$(sha256sum "$HTML" | cut -d" " -f1)" ]]'
if [[ -n "${PUBLISH_SCRIPT:-}" ]]; then r=$(ALLOW_HTTP_TEST=1 PRIVATE_URL="$B" "$PUBLISH_SCRIPT" 2026-10-16 2>&1 | tail -1); ok "publicador do box completo ($r)" '[[ "$r" == LINK:* ]]'; fi
h=$(login 10.0.0.1 000000); ok "senha errada -> 401 'Restam 4'" '[[ "$h" == *" 401 "* ]] && curl -s -H "X-Forwarded-For: 10.0.0.9" --data-urlencode password=111111 "$B/login" | grep -q "Restam 4"'
h=$(login 10.0.0.2 "$PW"); ok "senha certa -> 303 + cookie HttpOnly/SameSite/90 dias" '[[ "$h" == *" 303 "* && "$h" == *"HttpOnly"* && "$h" == *"SameSite=Lax"* && "$h" == *"Max-Age=7776000"* ]]'
CK=$(sed -n 's/^Set-Cookie: \([^;]*\);.*/\1/p' <<<"$h" | tr -d '\r')
body=$(curl -s -H "Cookie: $CK" "$B/"); ok "com cookie, / mostra o painel + link sair" '[[ ( "$body" == *"conteudo-protegido-de-teste"* || "$body" == *"id=\"kpis\""* ) && "$body" == *"/logout"* ]]'
r=$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: $CK" "$B/h/2026-10-16"); ok "com cookie, histórico /h/2026-10-16 -> 200" '[[ "$r" == 200 ]]'
r=$(curl -s -H "Cookie: $CK" "$B/h/"); ok "com cookie, lista do histórico" '[[ "$r" == *"/h/2026-10-16"* ]]'
r=$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: ${CK%?}x" "$B/"); ok "cookie adulterado -> 303 ($r)" '[[ "$r" == 303 ]]'
h=$(curl -s -o /dev/null -D - -X POST -H "Cookie: $CK" "$B/logout"); ok "sair -> apaga cookie (Max-Age=0)" '[[ "$h" == *"Max-Age=0"* ]]'
hdr=$(curl -s -o /dev/null -D - -H "Cookie: $CK" "$B/"); ok "cabeçalhos noindex/no-store" '[[ "$hdr" == *"X-Robots-Tag: noindex"* && "$hdr" == *"no-store"* ]]'
for i in 1 2 3 4; do login 10.0.0.3 12345$i >/dev/null; done
h=$(login 10.0.0.3 999999); ok "5º erro do mesmo IP -> 429 (bloqueado)" '[[ "$h" == *" 429 "* ]]'
h=$(login 10.0.0.3 "$PW"); ok "IP bloqueado não entra nem com a senha certa -> 429" '[[ "$h" == *" 429 "* ]]'
h=$(login 10.0.0.4 "$PW"); ok "outro IP entra normalmente -> 303" '[[ "$h" == *" 303 "* ]]'
CK2=$(sed -n 's/^Set-Cookie: \([^;]*\);.*/\1/p' <<<"$h" | tr -d '\r')
# global: até aqui 1+1+5 = 7 erros na hora; mais 14 de IPs distintos (3 por IP) -> 21 > 20
n=0; for ipn in 11 12 13 14 15; do for k in 1 2 3; do [[ $n -lt 14 ]] && login 10.0.1.$ipn 55555$k >/dev/null && n=$((n+1)); done; done
h=$(login 10.0.2.1 "$PW"); ok "após >20 erros/hora, bloqueio global (senha certa de IP novo -> 429)" '[[ "$h" == *" 429 "* ]]'
r=$(curl -s -o /dev/null -w '%{http_code}' -H "Cookie: $CK2" "$B/"); ok "durante bloqueio global, quem tem sessão continua vendo (200)" '[[ "$r" == 200 ]]'
st=$(printf 'Authorization: Bearer %s\n' "$(cat "$TOKEN_FILE")" | curl -s -H @- "$B/api/status"); ok "status mostra bloqueio global de 15 min" '[[ "$(jq -r .global_lock_min <<<"$st")" == 15 ]]'
stop; start env ALLOW_HTTP=1
h=$(login 10.0.2.2 "$PW"); ok "bloqueio global persiste após reinício (state.json) -> 429" '[[ "$h" == *" 429 "* ]]'
ok "log de tentativas gravado" '[[ $(grep -c login_fail "$D/logs/auth.log") -ge 15 && $(grep -c login_ok "$D/logs/auth.log") -ge 2 && $(grep -c login_blocked "$D/logs/auth.log") -ge 1 && $(grep -c token_fail "$D/logs/auth.log") -ge 1 ]]'
ok "senha não aparece no log/estado" '! grep -rqF -- "$PW" "$D/logs" "$D/state.json"'
stop

echo "== modo produção (atrás do Traefik)"; rm -f "$D/state.json"; start env
r=$(curl -s -o /dev/null -w '%{http_code} %{redirect_url}' -H 'Host: painel.exemplo' "$B/login"); ok "sem X-Forwarded-Proto=https -> 308 para https ($r)" '[[ "$r" == "308 https://painel.exemplo/login" ]]'
h=$(curl -s -o /dev/null -D - -H 'X-Forwarded-Proto: https' -H 'X-Forwarded-For: 10.9.9.9' --data-urlencode "password=$PW" "$B/login")
ok "cookie de produção: __Host-, Secure, HttpOnly, SameSite" '[[ "$h" == *"__Host-painel_sess="* && "$h" == *"Secure"* && "$h" == *"HttpOnly"* && "$h" == *"SameSite=Lax"* ]]'
ok "HSTS presente" '[[ "$h" == *"Strict-Transport-Security"* ]]'
stop; rm -rf "$D"
echo "== resultado: $pass ok, $fail falha(s)"; [[ $fail -eq 0 ]]
