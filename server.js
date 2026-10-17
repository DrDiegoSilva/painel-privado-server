// Painel privado — Instituto Diego Silva
// Serve o dashboard semanal (HTML) SOMENTE após login com senha verificada no servidor.
// Sem framework: node:http + bcryptjs. Configuração por variáveis de ambiente (nenhum segredo no código):
//   PASSWORD_HASH_B64    hash bcrypt da senha, em base64 (gerar com: printf '%s' SENHA | node hash-password.js --b64)
//   (ou PASSWORD_HASH     o hash bcrypt "cru")
//   PUBLISH_TOKEN_SHA256 sha256 (hex) do token de publicação usado pelo box (o token em si fica só no box)
//   SESSION_SECRET       opcional; sem ele, é gerado no 1º boot em DATA/session_secret (apagar o arquivo = derruba todas as sessões)
//   DATA_DIR             pasta persistente (padrão /data): dashboards/AAAA-MM-DD.html, logs/auth.log, state.json
//   PORT                 padrão 80          SESSION_DAYS  padrão 90         TRUST_PROXY  padrão 1 (Traefik na frente)
//   ALLOW_HTTP           "1" só para teste local (aceita requisição sem X-Forwarded-Proto=https e cookie sem Secure)
"use strict";
const http = require("http"), fs = require("fs"), path = require("path"), crypto = require("crypto");
const bcrypt = require("bcryptjs");

const env = process.env;
// PASSWORD_HASH_B64 = o mesmo hash em base64 (evita "$" do bcrypt sendo interpretado por painéis/shells)
const PASSWORD_HASH = env.PASSWORD_HASH_B64 ? Buffer.from(env.PASSWORD_HASH_B64, "base64").toString() : (env.PASSWORD_HASH || "");
const TOKEN_SHA = (env.PUBLISH_TOKEN_SHA256 || "").toLowerCase();
const DATA = env.DATA_DIR || "/data";
fs.mkdirSync(DATA, { recursive: true });
// SESSION_SECRET: se não vier no ambiente, é gerado no 1º boot e guardado em DATA/session_secret (600) — ninguém precisa copiá-lo.
const SECRET = env.SESSION_SECRET || (() => {
  const f = path.join(DATA, "session_secret");
  try { const v = fs.readFileSync(f, "utf8").trim(); if (v.length >= 32) return v; } catch (_) {}
  const v = crypto.randomBytes(48).toString("base64url"); fs.writeFileSync(f, v, { mode: 0o600 }); return v;
})();
const PORT = +(env.PORT || 80);
const SESSION_DAYS = +(env.SESSION_DAYS || 90);
const TRUST_PROXY = +(env.TRUST_PROXY || 1);
const ALLOW_HTTP = env.ALLOW_HTTP === "1";
if (!/^\$2[aby]\$\d\d\$/.test(PASSWORD_HASH) || !/^[0-9a-f]{64}$/.test(TOKEN_SHA) || SECRET.length < 32) {
  console.error("Config inválida: defina PASSWORD_HASH_B64 (bcrypt em base64), PUBLISH_TOKEN_SHA256 (64 hex); SESSION_SECRET, se definido, com >=32."); process.exit(1);
}
const DASH = path.join(DATA, "dashboards"), LOGS = path.join(DATA, "logs");
fs.mkdirSync(DASH, { recursive: true }); fs.mkdirSync(LOGS, { recursive: true });
const COOKIE = ALLOW_HTTP ? "painel_sess" : "__Host-painel_sess";   // __Host- exige Secure, Path=/ e sem Domain
const LOGO = fs.readFileSync(path.join(__dirname, "assets", "logo.png"));

// ------------------------------------------------------------------ limites de tentativa
// Por IP: 5 erros em 15 min -> IP bloqueado 15 min.
// Global: mais de 20 erros na última hora -> login bloqueado para TODOS por 15 min, dobrando a cada novo
//   disparo nas últimas 24 h (15, 30, 60 ... até 24 h). Quem já tem sessão (cookie) continua entrando.
// O estado é gravado em DATA/state.json (sobrevive a reinício do container).
const IP_MAX = 5, IP_WIN = 15 * 60e3, IP_BLOCK = 15 * 60e3;
const G_MAX = 20, G_WIN = 60 * 60e3, G_BASE = 15 * 60e3, G_CAP = 24 * 3600e3;
const STATE_FILE = path.join(DATA, "state.json");
let st = { ip: {}, gFails: [], gLocks: [], gUntil: 0 };
try { st = Object.assign(st, JSON.parse(fs.readFileSync(STATE_FILE, "utf8"))); } catch (_) {}
function saveState() {   // gravação síncrona e atômica (tráfego baixíssimo; não perde bloqueio se o container cair)
  const tmp = STATE_FILE + ".tmp"; fs.writeFileSync(tmp, JSON.stringify(st)); fs.renameSync(tmp, STATE_FILE); }
function prune(now) {
  st.gFails = st.gFails.filter(t => now - t < G_WIN);
  st.gLocks = st.gLocks.filter(t => now - t < 24 * 3600e3);
  for (const [k, v] of Object.entries(st.ip)) { v.f = v.f.filter(t => now - t < IP_WIN); if (!v.f.length && (v.until || 0) < now) delete st.ip[k]; }
}
function blockedFor(ip, now) {           // ms restantes de bloqueio (0 = liberado) e motivo
  prune(now);
  if (st.gUntil > now) return { ms: st.gUntil - now, why: "global" };
  const v = st.ip[ip]; if (v && (v.until || 0) > now) return { ms: v.until - now, why: "ip" };
  return { ms: 0 };
}
function registerFail(ip, now) {
  const v = st.ip[ip] || (st.ip[ip] = { f: [], until: 0 });
  v.f.push(now); if (v.f.length >= IP_MAX) { v.until = now + IP_BLOCK; v.f = []; }
  st.gFails.push(now);
  if (st.gFails.length > G_MAX) {
    st.gLocks.push(now);
    st.gUntil = now + Math.min(G_CAP, G_BASE * 2 ** (st.gLocks.length - 1));
    st.gFails = [];
  }
  saveState();
}
function registerOk(ip) { delete st.ip[ip]; saveState(); }

// ------------------------------------------------------------------ util
function clientIp(req) {
  const xff = (req.headers["x-forwarded-for"] || "").split(",").map(s => s.trim()).filter(Boolean);
  // com TRUST_PROXY=N, o IP real é o N-ésimo a partir do fim (o último é quem falou com o proxy)
  if (TRUST_PROXY > 0 && xff.length >= TRUST_PROXY) return xff[xff.length - TRUST_PROXY];
  return req.socket.remoteAddress || "?";
}
function logAuth(ev) {
  fs.appendFile(path.join(LOGS, "auth.log"), JSON.stringify(Object.assign({ ts: new Date().toISOString() }, ev)) + "\n", () => {});
}
const b64u = b => Buffer.from(b).toString("base64url");
function sign(s) { return crypto.createHmac("sha256", SECRET).update(s).digest("base64url"); }
function makeSession() {
  const p = b64u(JSON.stringify({ exp: Date.now() + SESSION_DAYS * 864e5, n: crypto.randomBytes(8).toString("hex") }));
  return p + "." + sign(p);
}
function validSession(req) {
  const m = (req.headers.cookie || "").split(/;\s*/).find(c => c.startsWith(COOKIE + "="));
  if (!m) return false;
  const [p, s] = m.slice(COOKIE.length + 1).split(".");
  if (!p || !s) return false;
  const exp = Buffer.from(sign(p)), got = Buffer.from(s);
  if (exp.length !== got.length || !crypto.timingSafeEqual(exp, got)) return false;
  try { return JSON.parse(Buffer.from(p, "base64url").toString()).exp > Date.now(); } catch (_) { return false; }
}
function cookieHdr(val, maxAgeSec) {
  return `${COOKIE}=${val}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAgeSec}` + (ALLOW_HTTP ? "" : "; Secure");
}
const BASE_HDR = {
  "X-Robots-Tag": "noindex, nofollow, noarchive", "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff",
  "X-Frame-Options": "DENY", "Cross-Origin-Opener-Policy": "same-origin", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
};
if (!ALLOW_HTTP) BASE_HDR["Strict-Transport-Security"] = "max-age=31536000";
function send(res, code, body, hdr = {}) {
  res.writeHead(code, Object.assign({}, BASE_HDR, { "Cache-Control": "no-store" }, hdr));
  res.end(body);
}
function readBody(req, max) {
  return new Promise((ok, ko) => { const ch = []; let n = 0;
    req.on("data", d => { n += d.length; if (n > max) { ko(new Error("grande demais")); req.destroy(); } else ch.push(d); });
    req.on("end", () => ok(Buffer.concat(ch))); req.on("error", ko); });
}
const esc = s => String(s).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const fmtMin = ms => Math.ceil(ms / 60e3);
function listDates() {
  return fs.readdirSync(DASH).filter(f => /^\d{4}-\d{2}-\d{2}\.html$/.test(f)).map(f => f.slice(0, 10)).sort();
}

// ------------------------------------------------------------------ páginas
function loginPage(msg = "", blocked = false) {
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="robots" content="noindex,nofollow,noarchive"><title>Acesso restrito</title><style>
*{box-sizing:border-box;margin:0;padding:0}html,body{height:100%;background:#f2efe6;color:#14332a;font-family:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.w{min-height:100%;display:flex;align-items:center;justify-content:center;padding:20px}
.c{width:100%;max-width:380px;background:#fff;border:1px solid rgba(20,51,42,.08);border-radius:14px;overflow:hidden;box-shadow:inset 0 1px 0 #fff,0 1px 1px rgba(20,51,42,.05),0 18px 40px -20px rgba(20,51,42,.35)}
.h{background:linear-gradient(180deg,#1f4a3d 0%,#14332a 100%);padding:18px 22px;display:flex;justify-content:center;border-bottom:3px solid #c9a227}.h img{height:46px;width:auto}
.b{padding:22px}h1{font-family:Georgia,"Times New Roman",serif;font-weight:600;font-size:21px}p.s{font-size:13px;color:#5f6d66;margin:4px 0 16px}
input{width:100%;font-size:20px;letter-spacing:.2em;padding:12px 13px;border:1px solid #cbd5d0;border-radius:9px;outline:none;background:#fbfaf6}
input:focus{border-color:#c9a227;box-shadow:0 0 0 3px rgba(201,162,39,.2)}
button{width:100%;margin-top:14px;font-size:16px;font-weight:600;padding:12px;border:0;border-radius:9px;background:#14332a;color:#fff;cursor:pointer}button:disabled{opacity:.55}
.e{color:#a23b2a;font-size:13px;min-height:18px;margin-top:10px}.f{font-size:11.5px;color:#8c9a93;text-align:center;margin-top:12px}
</style></head><body><div class="w"><form class="c" method="post" action="/login">
<div class="h"><img alt="Dr. Diego Silva" src="/assets/logo.png"></div><div class="b">
<h1>Painel restrito</h1><p class="s">Digite a senha para abrir. Neste aparelho ela fica lembrada por ${SESSION_DAYS} dias.</p>
<input type="password" name="password" inputmode="numeric" autocomplete="current-password" placeholder="Senha" autofocus required ${blocked ? "disabled" : ""}>
<button type="submit" ${blocked ? "disabled" : ""}>Entrar</button><div class="e">${esc(msg)}</div>
<div class="f">Acesso registrado · tentativas erradas bloqueiam o acesso temporariamente</div></div></form></div></body></html>`;
}
function withLogout(html) {
  const inj = `<form id="__lo" method="post" action="/logout" style="display:none"></form><script>(function(){var s=document.querySelector(".sub");` +
    `var a=document.createElement("a");a.href="#";a.textContent="sair";a.style.cssText="color:inherit;text-decoration:underline;margin-left:6px";` +
    `a.onclick=function(e){e.preventDefault();document.getElementById("__lo").submit()};` +
    `if(s){s.appendChild(document.createTextNode(" ·"));s.appendChild(a)}else{a.style.cssText="position:fixed;right:10px;bottom:8px;font:12px sans-serif;color:#5f6d66";document.body.appendChild(a)}})()</script>`;
  const i = html.lastIndexOf("</body>");
  return i > 0 ? html.slice(0, i) + inj + html.slice(i) : html + inj;
}
function historyPage(dates) {
  const li = dates.slice().reverse().map(d => `<li><a href="/h/${d}">Semana até ${d.slice(8, 10)}/${d.slice(5, 7)}/${d.slice(0, 4)}</a></li>`).join("");
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex">
<title>Histórico</title><style>body{font-family:system-ui,sans-serif;background:#f2efe6;color:#14332a;padding:24px}a{color:#14332a}li{margin:8px 0}</style></head>
<body><h2>Histórico</h2><p><a href="/">← mais recente</a></p><ul>${li || "<li>vazio</li>"}</ul>
<form method="post" action="/logout"><button>Sair</button></form></body></html>`;
}

// ------------------------------------------------------------------ servidor
const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, "http://x"); const p = url.pathname; const ip = clientIp(req); const now = Date.now();
    if (!ALLOW_HTTP && req.headers["x-forwarded-proto"] !== "https" && p !== "/healthz") {   // HTTPS obrigatório
      return send(res, 308, "", { Location: "https://" + (req.headers.host || "") + req.url });
    }
    if (p === "/healthz") return send(res, 200, "ok", { "Content-Type": "text/plain" });
    if (p === "/robots.txt") return send(res, 200, "User-agent: *\nDisallow: /\n", { "Content-Type": "text/plain" });
    if (p === "/assets/logo.png") return send(res, 200, LOGO, { "Content-Type": "image/png", "Cache-Control": "public, max-age=86400" });

    // ---- publicação pelo box (token)
    if (p.startsWith("/api/")) {   // token de 256 bits: vale só o bloqueio por IP (o global é contra adivinhar a senha)
      prune(now); const v = st.ip[ip]; const b = { ms: v && v.until > now ? v.until - now : 0 };
      if (b.ms) return send(res, 429, JSON.stringify({ error: "bloqueado", minutos: fmtMin(b.ms) }), { "Content-Type": "application/json", "Retry-After": String(Math.ceil(b.ms / 1e3)) });
      const tok = (req.headers.authorization || "").replace(/^Bearer\s+/i, "");
      const h = Buffer.from(crypto.createHash("sha256").update(tok).digest("hex")), want = Buffer.from(TOKEN_SHA);
      if (!tok || !crypto.timingSafeEqual(h, want)) { registerFail(ip, now); logAuth({ ev: "token_fail", ip, path: p }); return send(res, 401, '{"error":"token"}', { "Content-Type": "application/json" }); }
      let m;
      if (req.method === "PUT" && (m = p.match(/^\/api\/dashboards\/(\d{4}-\d{2}-\d{2})$/))) {
        const body = await readBody(req, 20 * 1024 * 1024);
        if (!/^<!doctype html>/i.test(body.slice(0, 50).toString())) return send(res, 400, '{"error":"não parece HTML"}', { "Content-Type": "application/json" });
        const f = path.join(DASH, m[1] + ".html"), tmp = f + ".tmp";
        fs.writeFileSync(tmp, body); fs.renameSync(tmp, f);
        const sha = crypto.createHash("sha256").update(body).digest("hex");
        logAuth({ ev: "publish", ip, date: m[1], bytes: body.length });
        return send(res, 201, JSON.stringify({ ok: true, date: m[1], bytes: body.length, sha256: sha, latest: listDates().pop() }), { "Content-Type": "application/json" });
      }
      if (req.method === "GET" && p === "/api/status") {
        const ds = listDates(), last = ds[ds.length - 1];
        const sha = last ? crypto.createHash("sha256").update(fs.readFileSync(path.join(DASH, last + ".html"))).digest("hex") : null;
        return send(res, 200, JSON.stringify({ latest: last || null, sha256: sha, count: ds.length, global_lock_min: st.gUntil > now ? fmtMin(st.gUntil - now) : 0 }), { "Content-Type": "application/json" });
      }
      return send(res, 404, '{"error":"rota"}', { "Content-Type": "application/json" });
    }

    // ---- login / logout
    if (p === "/login" && req.method === "GET") {
      if (validSession(req)) return send(res, 303, "", { Location: "/" });
      const b = blockedFor(ip, now);
      return send(res, b.ms ? 429 : 200, loginPage(b.ms ? `Muitas tentativas. Tente de novo em ${fmtMin(b.ms)} min.` : "", !!b.ms), { "Content-Type": "text/html; charset=utf-8" });
    }
    if (p === "/login" && req.method === "POST") {
      const b = blockedFor(ip, now);
      if (b.ms) { logAuth({ ev: "login_blocked", ip, why: b.why }); return send(res, 429, loginPage(`Muitas tentativas. Tente de novo em ${fmtMin(b.ms)} min.`, true), { "Content-Type": "text/html; charset=utf-8", "Retry-After": String(Math.ceil(b.ms / 1e3)) }); }
      const body = (await readBody(req, 4096)).toString();
      const pw = new URLSearchParams(body).get("password") || "";
      const ok = pw.length > 0 && pw.length <= 128 && await bcrypt.compare(pw, PASSWORD_HASH);
      const ua = String(req.headers["user-agent"] || "").slice(0, 120);
      if (!ok) {
        registerFail(ip, now); const b2 = blockedFor(ip, Date.now());
        logAuth({ ev: "login_fail", ip, ua, blocked: !!b2.ms });
        const left = st.ip[ip] ? IP_MAX - st.ip[ip].f.length : IP_MAX;
        return send(res, b2.ms ? 429 : 401, loginPage(b2.ms ? `Muitas tentativas. Tente de novo em ${fmtMin(b2.ms)} min.` : `Senha incorreta. Restam ${left} tentativa(s).`, !!b2.ms), { "Content-Type": "text/html; charset=utf-8" });
      }
      registerOk(ip); logAuth({ ev: "login_ok", ip, ua });
      return send(res, 303, "", { Location: "/", "Set-Cookie": cookieHdr(makeSession(), SESSION_DAYS * 86400) });
    }
    if (p === "/logout") return send(res, 303, "", { Location: "/login", "Set-Cookie": cookieHdr("", 0) });

    // ---- conteúdo protegido
    if (!validSession(req)) return send(res, 303, "", { Location: "/login" });
    let file = null; let m;
    if (p === "/" ) { const d = listDates().pop(); if (d) file = d; }
    else if (p === "/h" || p === "/h/") return send(res, 200, historyPage(listDates()), { "Content-Type": "text/html; charset=utf-8" });
    else if ((m = p.match(/^\/h\/(\d{4}-\d{2}-\d{2})$/))) file = m[1];
    if (!file) return send(res, p === "/" ? 503 : 404, p === "/" ? "Nenhum painel publicado ainda." : "Não encontrado.", { "Content-Type": "text/plain; charset=utf-8" });
    const f = path.join(DASH, file + ".html");
    if (!fs.existsSync(f)) return send(res, 404, "Não encontrado.", { "Content-Type": "text/plain; charset=utf-8" });
    return send(res, 200, withLogout(fs.readFileSync(f, "utf8")), { "Content-Type": "text/html; charset=utf-8" });
  } catch (e) {
    console.error(e); if (!res.headersSent) send(res, 500, "erro", { "Content-Type": "text/plain" });
  }
});
server.listen(PORT, () => console.log(`painel-privado ouvindo na porta ${PORT} (dados em ${DATA})`));
