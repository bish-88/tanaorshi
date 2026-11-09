// 新しい棚卸ロス分析レポート(.xls)を data/data.enc に追加する（前のレポートは残す）
// 使いかた:  TANA_PW='パスワード' node tools/update-data.mjs <レポート.xls> [もう1つ.xls ...]
//   ・xlsx パッケージが必要:  npm i xlsx@0.18.5  （このフォルダの外でも可。NODE_PATH で指定）
//   ・パスワードはリポジトリに保存しない
import fs from "node:fs";
import path from "node:path";
import { webcrypto as crypto } from "node:crypto";
import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const XLSX = require("xlsx");

const PW = process.env.TANA_PW;
const files = process.argv.slice(2);
if (!PW || !files.length) { console.error("TANA_PW='…' node tools/update-data.mjs file.xls"); process.exit(1); }
const ENC = path.join(path.dirname(new URL(import.meta.url).pathname), "..", "data", "data.enc");
const ITER = 600000;

const b64e = u => Buffer.from(u).toString("base64");
const b64d = t => new Uint8Array(Buffer.from(t, "base64"));
const pipe = async (bytes, stream) => new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(stream)).arrayBuffer());
async function keyFrom(pw, salt, iter) {
  const base = await crypto.subtle.importKey("raw", new TextEncoder().encode(pw), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function decrypt(obj, pw) {
  let p = new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64d(obj.iv) }, await keyFrom(pw, b64d(obj.salt), obj.iter), b64d(obj.ct)));
  if (obj.gzip) p = await pipe(p, new DecompressionStream("gzip"));
  return JSON.parse(new TextDecoder().decode(p));
}
async function encrypt(list, pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const plain = await pipe(new TextEncoder().encode(JSON.stringify(list)), new CompressionStream("gzip"));
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv }, await keyFrom(pw, salt, ITER), plain));
  return JSON.stringify({ v: 1, kdf: "PBKDF2-SHA256", iter: ITER, gzip: true, salt: b64e(salt), iv: b64e(iv), ct: b64e(ct) });
}
const fmtD = d => `${d.getFullYear()}/${String(d.getMonth() + 1).padStart(2, "0")}/${String(d.getDate()).padStart(2, "0")}`;

// index.html の extract() と同じ処理
function extract(file) {
  const wb = XLSX.read(fs.readFileSync(file), { type: "buffer" });
  const fname = path.basename(file);
  const sn = wb.SheetNames.find(n => /^ITEMDATA/i.test(n));
  if (!sn) throw new Error(`${fname}: ITEMDATA シートがありません`);
  const all = XLSX.utils.sheet_to_json(wb.Sheets[sn], { header: 1, raw: true, defval: "" });
  const rows = all.filter(r => String(r[0]).trim() && String(r[2]).trim()).map(r => { let e = r.length; while (e > 0 && r[e - 1] === "") e--; return r.slice(0, e); });
  let rdate = null;
  const st = wb.Sheets["STATUS"];
  if (st && st["C1"] && typeof st["C1"].v === "number") { const p = XLSX.SSF.parse_date_code(st["C1"].v); rdate = new Date(p.y, p.m - 1, p.d); }
  if (!rdate) { const m = fname.match(/(20\d{2})(\d{2})(\d{2})/); if (m) rdate = new Date(+m[1], +m[2] - 1, +m[3]); }
  if (!rdate) rdate = new Date();
  return { id: fmtD(rdate) + "|" + fname, fname, rdate: rdate.getTime(), savedAt: Date.now(), rows };
}

let list = [];
if (fs.existsSync(ENC)) list = await decrypt(JSON.parse(fs.readFileSync(ENC, "utf8")), PW); // パスワードがちがうとここで失敗
for (const f of files) {
  const rep = extract(f);
  list = list.filter(x => x.id !== rep.id && fmtD(new Date(x.rdate)) !== fmtD(new Date(rep.rdate)));
  list.push(rep);
  console.log(`追加: ${fmtD(new Date(rep.rdate))}  ${rep.fname}  (${rep.rows.length}行)`);
}
list.sort((a, b) => b.rdate - a.rdate);
fs.writeFileSync(ENC, await encrypt(list, PW));
console.log(`data.enc を更新しました。レポート ${list.length}件: ` + list.map(x => fmtD(new Date(x.rdate))).join(", "));
