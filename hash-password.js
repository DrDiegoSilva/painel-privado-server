// Gera o hash bcrypt (custo 12) da senha lida do stdin, sem ecoar.  uso:  printf '%s' "$SENHA" | node hash-password.js [--b64]
const bcrypt = require("bcryptjs");
let s = ""; process.stdin.on("data", d => s += d).on("end", () => {
  s = s.replace(/\r?\n$/, ""); if (!s) { console.error("senha vazia"); process.exit(1); }
  const h = bcrypt.hashSync(s, 12);
  process.stdout.write((process.argv.includes("--b64") ? Buffer.from(h).toString("base64") : h) + "\n");
});
