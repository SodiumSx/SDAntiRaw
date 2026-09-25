// /api/payload v4 — REQUIRE key Turnstile luôn, ticket bind (IP/24 + HWID).
// Chain AI cũ: payload?s=..&k=<ticket fresh public>&hwid=recrack-01&place=0&key=db123 -> DIE toàn tập:
//   place=0 DIE (validPlace), key=db123 DIE (verifyUserKey), hwid tự khai DIE (ticket bind HWID).

const fs = require("fs");
const path = require("path");
const P = require("./_protect");

// SOURCE THẬT — 2 tầng:
//   Tầng 2 (trong): code đã obfuscate bằng Clyde lúc build (api/_code.obf.lua).
//   Tầng 1 (ngoài): XOR transport + stub đa hình theo từng request (dưới).
// Cách nạp: copy source.lua.example -> source.lua (PRIVATE, gitignore),
// chạy: node scripts/obfuscate-source.mjs [--preset=medium|paranoid]
// -> sinh api/_code.obf.lua rồi deploy. Không có file đó thì dùng demo dưới.
const LUA_CODE = `-- sodiumhub
print("sodiumhub")
`;

let OBF_SOURCE = null;
try {
  const p = path.join(__dirname, "_code.obf.lua");
  const s = fs.readFileSync(p, "utf8");
  if (s && s.length > 50) OBF_SOURCE = s;
} catch (e) {
  OBF_SOURCE = null;
}

function getLuaBody() {
  return OBF_SOURCE || LUA_CODE;
}

function randName() {
  const abc = "abcdef";
  let s = "_";
  for (let i = 0; i < 5; i++) s += abc[Math.floor(Math.random() * abc.length)] + Math.floor(Math.random() * 10);
  return s;
}

// Stub đa hình mỗi request: tên biến random + junk math -> AI không viết 1 parser xài mãi được.
// Key = sig|hwid (string) -> copy blob sang HWID khác là hỏng.
function buildStub(blobB64, sigHex) {
  const vB = randName(), vG = randName(), vC = randName(), vM = randName();
  const vD = randName(), vH = randName(), vK = randName(), vR = randName();
  const vS = randName(), vJ = randName();
  const junk = Math.floor(Math.random() * 900000 + 100000);
  return `-- sodium v4 stub
local ${vB}='${blobB64}'
local ${vG}='${sigHex}'
local ${vC}='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
local ${vM}={}
for ${vJ}=1,#${vC} do ${vM}[${vC}:sub(${vJ},${vJ})]=${vJ}-1 end
local function ${vD}(${vH})
 ${vH}=${vH}:gsub('[^'..${vC}..'=]','')
 local ${vR}={}
 local _i=1
 while _i<=#${vH} do
  local _a,_b,_e,_f=${vM}[${vH}:sub(_i,_i)] or 0,${vM}[${vH}:sub(_i+1,_i+1)] or 0,${vM}[${vH}:sub(_i+2,_i+2)] or 0,${vM}[${vH}:sub(_i+3,_i+3)] or 0
  local _n=_a*262144+_b*4096+_e*64+_f
  table.insert(${vR},string.char(math.floor(_n/65536)%256))
  if ${vH}:sub(_i+2,_i+2)~='=' then table.insert(${vR},string.char(math.floor(_n/256)%256)) end
  if ${vH}:sub(_i+3,_i+3)~='=' then table.insert(${vR},string.char(_n%256)) end
  _i=_i+4
 end
 return table.concat(${vR})
end
if typeof(game)~='Instance' then error('unauthorized [sodium v4]') end
local ${vH}=(typeof(gethwid)=='function' and gethwid() or game:GetService('RbxAnalyticsService'):GetClientId())
${vH}=tostring(${vH} or 'unknown'):gsub('[^%w%-%.:]','')
local ${vK}=${vG}..'|'..${vH}
local ${vR}=${vD}(${vB})
local ${vS}={}
for _i=1,#${vR} do ${vS}[_i]=string.char(bit32.bxor(${vR}:byte(_i),${vK}:byte(((_i-1)%#${vK})+1))) end
local _junk=${junk} -- integrity
if (_junk%7==9999) then error('x') end
loadstring(table.concat(${vS}))()
`;
}

async function handler(req, res) {
  P.noCache(res);
  if (P.rateLimited(req)) return P.sendBlack(req, res);
  if (!P.isRoblox(req)) return P.sendBlack(req, res);

  // Fake mode: TRANG TINH — không có source, mọi request chỉ ăn tarpit/error.
  if (P.isFake(req)) return P.sendLuaError(res);

  const ip = P.getIp(req);
  const q = req.query || {};
  const s = (q.s || "").toString();
  const k = (q.k || "").toString(); // "<ticket>.<sig>"
  const hwid = P.sanitizeHwid(q.hwid);
  const place = P.sanitizePlace(q.place);
  const nonce = (q.n || "").toString();
  const job = ((q.job) || "").toString().replace(/[^A-Za-z0-9\-]/g, "").slice(0, 64);
  const ukey = ((q.key) || "").toString().replace(/[^0-9a-f.]/g, "").slice(0, 80);

  if (s !== P.SCRIPT_ID) return P.sendLuaError(res);
  if (!P.validHwid(hwid)) return P.sendLuaError(res);
  if (!P.validPlace(place)) return P.sendLuaError(res);
  if (!P.placeAllowed(place)) {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).send(`error("wrong game [sodium v4]")`);
  }
  // JobId attestation nhẹ: real server luôn có JobId UUID 36 ký tự, Studio cho 'unknown'.
  // AI gửi bừa place=1/job=test -> DIE ở format. Không chặn cứng Studio (cho 'unknown' qua).
  if (job && job !== "unknown" && !/^[A-Za-z0-9\-]{8,64}$/.test(job)) return P.sendLuaError(res);

  // AI chạy từ cloud (OpenAI/Azure/GCP): IP datacenter -> bẫy tarpit dài (tốn token AI), không báo lý do.
  // Người mạng dân cư -> qua như bình thường. Fail-open nếu API check hỏng.
  try {
    if (await P.isDatacenterIP(ip)) return P.sendTarpit(res);
  } catch (e) {}
  if (P.aiSignals(req) >= 3) return P.sendTarpit(res);

  // v4: key Turnstile BẮT BUỘC cho mọi request — không còn đường free/isKnownHwid.
  // key=db123 sai -> DIE ở đây trước cả khi check ticket (đúng case AI vừa bẻ).
  if (!ukey || !P.verifyUserKey(ukey, hwid)) {
    const host = P.getHost(req);
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).send(`error("verify required: open https://${host}/api/verify?hwid=${hwid} [sodium v4]")`);
  }

  // k = ticket.sig (ticket = rand16.ts10, sig = HMAC bind subnet+HWID lúc xin raw)
  const m = k.match(/^([0-9a-f]{16}\.\d{10})\.([0-9a-f]{64})$/);
  if (!m) return P.sendLuaError(res);
  const ticket = m[1];
  const sig = m[2];
  // 1) Ticket phải bind đúng subnet IP + đúng HWID đã verify -> đổi hwid (recrack-01) DIE
  if (!P.verifyTicket(ticket, sig, ip, hwid)) return P.sendLuaError(res);
  // 2) PoW: phải exec Lua mới có nonce -> curl chay DIE
  if (!P.powVerify(ticket, nonce)) return P.sendLuaError(res);
  // 3) Replay: 1 ticket 1 lần (per-instance; muốn tuyệt đối thì dùng KV/Redis)
  if (!P.markUsed(ticket)) return P.sendLuaError(res);
  // 4) Throttle: chặn xoay HWID dump hàng loạt
  if (!P.checkHwidThrottle(hwid, ip)) return P.sendLuaError(res);
  P.rememberHwid(hwid);

  // Mã hoá bằng key STRING (sig|hwid) để stub Lua khớp 100%.
  // Watermark kép (comment + string): comment bị beautifier strip thì string vẫn lộ HWID leak.
  // Đặt TRƯỚC code obfuscated (đã chạy Clyde lúc build) nên không bị strip lúc obfuscate.
  const exec = ((q.exec) || "").toString().replace(/[^A-Za-z0-9_\-.\s]/g, "").slice(0, 24);
  const keyStr = `${sig}|${hwid}`;
  const wm = `${hwid}|${place}|${job}|${exec}|${Date.now()}`;
  const code = `-- licensed:${wm}\nlocal __SODIUM_LIC_Q7Z9=${JSON.stringify(wm)}\n` + getLuaBody();
  const keyBuf = Buffer.from(keyStr, "utf8");
  const blob = P.xorCrypt(Buffer.from(code, "utf8"), keyBuf).toString("base64");

  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).send(buildStub(blob, sig));
}

module.exports = handler;
module.exports.default = handler;
