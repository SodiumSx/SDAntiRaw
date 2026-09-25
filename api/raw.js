// /api/raw v3 — anti-AI: ticket bind IP/24 + PoW Lua + Roblox env attestation
// Luồng: executor HttpGet(/api/raw) -> loader chứa ticket.sig (bind subnet IP xin raw, 180s, 1 lần)
// -> loader CHECK môi trường Roblox thật, giải PoW bằng Lua, rồi gọi /api/payload?s&k&hwid&place&n&job
// AI chỉ curl mà không exec Luau / không ở IP dân cư / không có JobId thật -> DIE toàn tập.

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

function buildLoader(host, ticket, sig, ukey) {
  // Tên biến random mỗi request -> tool hardcode _s/_t/_u chết.
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
  // Key cá nhân (?key= từ loader riêng sau Turnstile) được truyền tiếp xuống payload.
  const keyTail = ukey ? `..'&key=${ukey}'` : "";

  return `-- sodium loader v3
local ${vS}=${idLua}
local ${vT}='${ticket}.${sig}'
-- [1] Roblox env attestation: AI chạy python/plain-lua không có game/workspace/JobId là DIE ngay
if typeof(game)~='Instance' or typeof(workspace)~='Instance' then error('unauthorized [sodium v3]') end
local ${vG}=(typeof(gethwid)=='function' and gethwid() or game:GetService('RbxAnalyticsService'):GetClientId())
local ${vH}=tostring(${vG} or 'unknown'):gsub('[^%w%-%.:]','')
if #${vH}<3 then error('unauthorized [sodium v3]') end
local ${vP}=tostring(game.PlaceId)
local ${vJ}=tostring(game.JobId or 'unknown')
-- [2] PoW anti-curl: phải EXEC Lua mới ra nonce, AI chỉ copy URL là DIE (server verify hash % ${P.POW_DIFFICULTY} == 0)
local function ${vF}(${vW})
 local _h=5381
 for _i=1,#${vW} do _h=(_h*33+${vW}:byte(_i))%4294967296 end
 return _h
end
local ${vN}=0
while ${vF}('${ticket}|'..${vN})%${P.POW_DIFFICULTY}~=0 do
 ${vN}=${vN}+1
 if ${vN}>5000000 then error('unauthorized [sodium v3]') end
end
-- [3] Thu thập executor (để server watermark + phát hiện fake hàng loạt)
local ${vE}=(typeof(identifyexecutor)=='function' and identifyexecutor() or 'unknown')
local ${vU}=(${hostLua})..'?s='..${vS}..'&k='..${vT}..'&hwid='..${vH}..'&place='..${vP}..'&n='..tostring(${vN})..'&job='..${vJ}:gsub('[^%w%-]','')..'&exec='..tostring(${vE}):gsub('[^%w%-%. ]',''):sub(1,24)${keyTail}
loadstring(game:HttpGet(${vU}))()
`;
}

// Loader giả cho AI/datacenter: nhìn Y CHANG thật (ticket format chuẩn) nhưng sig random -> payload 100% DIE.
// AI tưởng bypass được, mang về phân tích tốn token vô ích.
function buildFakeLoader(host) {
  const fakeTicket = P.makeTicket();
  const fakeSig = "0".repeat(64).replace(/0/g, () => Math.floor(Math.random() * 16).toString(16));
  return buildLoader(host, fakeTicket, fakeSig, "");
}

async function handler(req, res) {
  P.noCache(res);
  if (P.rateLimited(req)) return P.sendBlack(req, res);
  if (!P.isRoblox(req)) return P.sendBlack(req, res);

  const ip = P.getIp(req);
  const ukey = (((req.query || {}).key) || "").toString().replace(/[^0-9a-f.]/g, "").slice(0, 80);

  // AI chạy từ cloud (OpenAI/Azure/GCP): trả loader GIẢ để nó tưởng thật, payload sau đó tarpit.
  // Fail-open cho user thật: nếu API check hỏng -> coi như residential -> cho ticket thật.
  try {
    if (await P.isDatacenterIP(ip)) {
      res.setHeader("Content-Type", "text/plain; charset=utf-8");
      return res.status(200).send(buildFakeLoader(P.getHost(req)));
    }
  } catch (e) {}
  // Tín hiệu bot rõ rệt (UA python/curl, header browser) -> cũng trả giả.
  if (P.aiSignals(req) >= 3) {
    res.setHeader("Content-Type", "text/plain; charset=utf-8");
    return res.status(200).send(buildFakeLoader(P.getHost(req)));
  }

  const ticket = P.makeTicket();
  const sig = P.signTicket(ticket, ip); // bind /24 subnet
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).send(buildLoader(P.getHost(req), ticket, sig, ukey));
}

module.exports = handler;
module.exports.default = handler;
