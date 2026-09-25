// /api/payload v3 — anti-AI: ticket bind IP/24 + PoW Lua + Turnstile gate cho HWID lạ.
// AI fetch ?s=&k=&hwid=test với UA fake -> DIE. Phải: qua /api/raw (residential IP) lấy ticket
// fresh bind subnet, exec Lua giải PoW, gửi đúng hwid+place+nonce+job, HWID lạ phải có ?key= Turnstile.

const P = require("./_protect");

// SOURCE THẬT — dán code vào giữa 2 dấu ` bên dưới (ghi đè 2 dòng demo).
// Chỉ web THẬT mới trả biến này (web fake không bao giờ đụng tới).
// Lưu ý: tránh dấu backtick và ${ trong source. Để repo PRIVATE.
const LUA_CODE = `-- sodiumhub
print("sodiumhub")
`;

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
  return `-- sodium v3 stub
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
if typeof(game)~='Instance' then error('unauthorized [sodium v3]') end
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
    return res.status(200).send(`error("wrong game [sodium v3]")`);
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

  // k = ticket.sig  (ticket = rand16.ts10 , sig = hmac64 bind /24 subnet lúc xin raw)
  const m = k.match(/^([0-9a-f]{16}\.\d{10})\.([0-9a-f]{64})$/);
  if (!m) return P.sendLuaError(res);
  const ticket = m[1];
  const sig = m[2];
  // 1) Ticket phải bind đúng subnet IP hiện tại -> share ticket sang IP khác DIE
  if (!P.verifyTicket(ticket, sig, ip)) return P.sendLuaError(res);
  // 2) PoW: phải exec Lua mới có nonce -> curl chay DIE
  if (!P.powVerify(ticket, nonce)) return P.sendLuaError(res);
  // 3) Replay: 1 ticket 1 lần
  if (!P.markUsed(ticket)) return P.sendLuaError(res);
  // 4) Throttle ngầm free
  if (!P.checkHwidThrottle(hwid, ip)) return P.sendLuaError(res);

  // 5) HWID lạ chưa từng thấy + không có key Turnstile -> bắt verify browser 1 lần.
  // AI curl với hwid random mỗi lần DIE ở đây (không giải được Turnstile bằng curl).
  // User thật: mở /api/verify?hwid=... 1 lần, lấy loader cá nhân (?key=) là xong 365 ngày.
  const hasKey = ukey && P.verifyUserKey(ukey, hwid);
  if (!P.isKnownHwid(hwid) && !hasKey) {
    // Nếu key sai định dạng mà HWID lạ -> cũng bắt verify (không lộ thêm info).
    const host = P.getHost(req);
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).send(`error("verify required: open https://${host}/api/verify?hwid=${hwid} [sodium v3]")`);
  }
  P.rememberHwid(hwid);

  // Mã hoá bằng key STRING (sig|hwid) để stub Lua khớp 100%.
  // Watermark: nhúng HWID/place/job/exec/time trước khi mã hoá — source leak là biết ai leak.
  const exec = ((q.exec) || "").toString().replace(/[^A-Za-z0-9_\-.\s]/g, "").slice(0, 24);
  const keyStr = `${sig}|${hwid}`;
  const code = `-- licensed:${hwid}|${place}|${job}|${exec}|${Date.now()}\n` + LUA_CODE;
  const keyBuf = Buffer.from(keyStr, "utf8");
  const blob = P.xorCrypt(Buffer.from(code, "utf8"), keyBuf).toString("base64");

  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).send(buildStub(blob, sig));
}

module.exports = handler;
module.exports.default = handler;
