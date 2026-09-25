// /api/raw v4 — ACCESS CONTROL thật: KHÔNG key thì KHÔNG ticket.
// Luồng đúng duy nhất:
//   browser: GET /api/verify?hwid=... + Turnstile -> loader cá nhân (?key= bound HWID)
//   executor: loader cá nhân thu HWID -> GET /api/raw?key=...&hwid=... -> ticket bind (IP/24 + HWID)
//   executor: stage2 exec Lua (env check + PoW) -> GET /api/payload?s&k&hwid&place&n&job&key
// Chain cũ của AI (raw public -> ticket fresh -> payload hwid tự khai recrack-01) DIE ở bước 1.

const P = require("./_protect");

function randName() {
  const abc = "abcdef";
  let s = "_";
  for (let i = 0; i < 5; i++) s += abc[Math.floor(Math.random() * abc.length)] + Math.floor(Math.random() * 10);
  return s;
}

// Chia host thành 3 mảnh + dựng path từng khúc -> regex "https://.../api/payload" chết hẳn.
function splitHostLua(host) {
  const c1 = Math.max(3, Math.floor(host.length / 3));
  const c2 = Math.max(c1 + 3, Math.floor((host.length * 2) / 3));
  const a = host.slice(0, c1);
  const b = host.slice(c1, c2);
  const c = host.slice(c2);
  return `"https"..'://'..'${a}'..'${b}'..'${c}'.."/a"..'pi/'.."pay"..'load'`;
}

// Chia script_id để regex local _s="..." cũ không match.
function splitIdLua(id) {
  const cut = Math.max(2, Math.floor(id.length / 2));
  return `'${id.slice(0, cut)}'..'${id.slice(cut)}'`;
}

function buildLoader(host, ticket, sig, ukey, boundHwid) {
  const vS = randName();
  const vT = randName();
  const vG = randName();
  const vH = randName();
  const vP = randName();
  const vU = randName();
  const vN = randName();
  const vJ = randName();
  const vF = randName();
  const vW = randName();
  const vE = randName();
  const idLua = splitIdLua(P.SCRIPT_ID);
  const hostLua = splitHostLua(host);
  const safeBound = (boundHwid || "").replace(/[^A-Za-z0-9_\-.:]/g, "").slice(0, 80);
  const keyTail = ukey ? `..'&key=${ukey}'` : "";

  return `-- sodium loader v4
local ${vS}=${idLua}
local ${vT}='${ticket}.${sig}'
if typeof(game)~='Instance' or typeof(workspace)~='Instance' then error('unauthorized [sodium v4]') end
local ${vG}=(typeof(gethwid)=='function' and gethwid() or game:GetService('RbxAnalyticsService'):GetClientId())
local ${vH}=tostring(${vG} or 'unknown'):gsub('[^%w%-%.:]','')
if ${vH}~='${safeBound}' then error("verify required: open https://${host}/api/verify?hwid="..${vH}.." [sodium v4]") end
local ${vP}=tostring(game.PlaceId)
local ${vJ}=tostring(game.JobId or 'unknown')
local function ${vF}(${vW})
 local _h=5381
 for _i=1,#${vW} do _h=(_h*33+${vW}:byte(_i))%4294967296 end
 return _h
end
local ${vN}=0
while ${vF}('${ticket}|'..${vN})%${P.POW_DIFFICULTY}~=0 do
 ${vN}=${vN}+1
 if ${vN}>5000000 then error('unauthorized [sodium v4]') end
end
local ${vE}=(typeof(identifyexecutor)=='function' and identifyexecutor() or 'unknown')
local ${vU}=(${hostLua})..'?s='..${vS}..'&k='..${vT}..'&hwid='..${vH}..'&place='..${vP}..'&n='..tostring(${vN})..'&job='..${vJ}:gsub('[^%w%-]','')..'&exec='..tostring(${vE}):gsub('[^%w%-%. ]',''):sub(1,24)${keyTail}
loadstring(game:HttpGet(${vU}))()
`;
}

async function handler(req, res) {
  P.noCache(res);
  if (P.rateLimited(req)) return P.sendBlack(req, res);
  if (!P.isRoblox(req)) return P.sendBlack(req, res);

  const ip = P.getIp(req);
  const host = P.getHost(req);
  const q = req.query || {};
  const ukey = ((q.key) || "").toString().replace(/[^0-9a-f.]/g, "").slice(0, 80);
  const uhwid = P.sanitizeHwid(q.hwid);

  // Cửa chính v4: thiếu key hoặc thiếu hwid -> KHÔNG ticket, chỉ helper báo link verify.
  // Chain AI cũ (GET /api/raw trơn -> ticket fresh) DIE tại đây.
  if (!ukey || !P.validHwid(uhwid) || !P.verifyUserKey(ukey, uhwid)) {
    return P.sendVerifyHelper(res, host);
  }

  // Key đúng nhưng IP datacenter -> tarpit (chặn AI solve Turnstile 1 lần rồi scrape từ cloud).
  // User VPN datacenter bị ảnh hưởng: tradeoff đã ghi rõ, dùng mạng dân cư để chạy.
  try {
    if (await P.isDatacenterIP(ip)) return P.sendTarpit(res);
  } catch (e) {}
  if (P.aiSignals(req) >= 3) return P.sendTarpit(res);

  if (!P.checkHwidThrottle(uhwid, ip)) return P.sendLuaError(res);

  // Ticket bind CẢ subnet IP lẫn HWID đã verify -> đổi hwid lúc gọi payload là DIE.
  const ticket = P.makeTicket();
  const sig = P.signTicket(ticket, ip, uhwid);
  P.rememberHwid(uhwid);
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).send(buildLoader(host, ticket, sig, ukey, uhwid));
}

module.exports = handler;
module.exports.default = handler;
