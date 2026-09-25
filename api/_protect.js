// Shared protect lib (v2) — dùng chung cho /api/raw và /api/payload
// Mục tiêu: secret KHÔNG bao giờ xuống client, ticket 1 lần + HMAC + payload mã hoá.

const crypto = require("crypto");

const SCRIPT_ID = "sodiumhub_main";
const LOADER_SECRET = (process.env.LOADER_SECRET || "d4f3788b69f4cab33095e28b7261cf909a28a061eb6039598aa2e554d6a9859b").trim();
const ALLOWED_PLACES = (process.env.ALLOWED_PLACES || "").trim();
// Tắt verify Turnstile tạm thời: public loader chạy thẳng, không cần key.
// Muốn bật lại: set Env REQUIRE_KEY=1 trên Vercel rồi deploy lại.
const REQUIRE_KEY = (process.env.REQUIRE_KEY || "").trim() === "1";

// Cloudflare Turnstile — checkpoint 1 lan cho HWID la (nguoi tich 10s, AI curl bo tay).
// Site key hien o web, Secret chi server dung. Env (neu set) uu tien hon hardcode.
const TURNSTILE_SITE = (process.env.TURNSTILE_SITE || "0x4AAAAAAFBxUWLQO4GhCRhw").trim();
const TURNSTILE_SECRET = (process.env.TURNSTILE_SECRET || "0x4AAAAAAFBxUd-kPzbyqFQ2wI2FrEJjsyo").trim();

// Key ca nhan bound HWID (stateless, han 365 ngay): key = exp.sig
// sig = HMAC(LOADER_SECRET, "vkey|hwid|exp"). Khong DB, khong luu tru.
function makeUserKey(hwid, days) {
  const exp = Math.floor(Date.now() / 1000) + (days || 365) * 86400;
  const sig = crypto.createHmac("sha256", LOADER_SECRET).update(`vkey|${hwid}|${exp}`).digest("hex");
  return `${exp}.${sig}`;
}

function verifyUserKey(key, hwid) {
  if (typeof key !== "string" || typeof hwid !== "string") return false;
  const m = key.match(/^(\d{10})\.([0-9a-f]{64})$/);
  if (!m) return false;
  const exp = parseInt(m[1], 10);
  if (exp * 1000 < Date.now()) return false;
  const expect = crypto.createHmac("sha256", LOADER_SECRET).update(`vkey|${hwid}|${exp}`).digest("hex");
  const a = Buffer.from(expect, "hex");
  const b = Buffer.from(m[2], "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

async function checkTurnstile(token, ip) {
  try {
    if (!token || token.length < 10) return false;
    const params = new URLSearchParams({ secret: TURNSTILE_SECRET, response: token });
    if (ip && ip !== "unknown") params.append("remoteip", ip);
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: params.toString(),
    });
    const j = await r.json();
    return !!(j && j.success);
  } catch (e) {
    return false;
  }
}

// Chung 1 repo, 2 project Vercel — code tu nhan dien theo domain, KHONG can set Env:
//   THAT: sodiumsxhub-loader.vercel.app (giu source, browser tu da sang web bay)
//   BAY : sodiumsxhubb-loader.vercel.app (trang tinh, payload chi tra loi)
const FAKE_HOST = "https://sodiumsxhubb-loader.vercel.app";
const REAL_HOST = "sodiumsxhub-loader.vercel.app";

function isFake(req) {
  try {
    return getHost(req).toLowerCase() === "sodiumsxhubb-loader.vercel.app";
  } catch (e) {
    return false;
  }
}

// Ticket sống 180s, chống replay bằng cache memory (per-instance).
// Muốn chống replay tuyệt đối cross-instance -> dùng Vercel KV / Upstash Redis.
const TICKET_TTL = 180;
const POW_DIFFICULTY = 512; // hash(ticket|nonce) % 512 == 0 -> TB ~256 vòng Lua, curl chay tay DIE
const usedTickets = new Map(); // ticket -> expireAt(ms)
const ipHits = new Map(); // ip -> [timestamps]
const seenHwids = new Map(); // hwid -> firstSeen(ms), để bắt HWID lạ phải verify Turnstile

// Chan AI chay cloud ma KHONG phien nguoi: AI agent (ChatGPT/Claude/API) chay tu
// datacenter (AWS/Azure/GCP) -> hosting=true -> chan am. Nguoi choi mang dan cu -> qua.
// Fail-open: API check hong/timeout -> cho qua (khong de user that bi van oan).
// Nguoi xai VPN datacenter co the bi anh huong (danh doi chap nhan duoc, canh bao user).
const ipHostCache = new Map(); // ip -> { hosting, exp }

function isPrivateIP(ip) {
  return /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|::1|fc00:|fe80:)/i.test(ip || "");
}

async function isDatacenterIP(ip) {
  if (!ip || ip === "unknown" || isPrivateIP(ip)) return false;
  const now = Date.now();
  const c = ipHostCache.get(ip);
  if (c && c.exp > now) return c.hosting;
  try {
    const ctl = new AbortController();
    const timer = setTimeout(() => { try { ctl.abort(); } catch (e) {} }, 2500);
    const r = await fetch(`http://ip-api.com/json/${encodeURIComponent(ip)}?fields=status,hosting,query`, { signal: ctl.signal });
    clearTimeout(timer);
    const j = await r.json();
    const hosting = !!(j && j.status === "success" && j.hosting);
    ipHostCache.set(ip, { hosting, exp: now + 6 * 3600000 });
    if (ipHostCache.size > 5000) {
      for (const [k, v] of ipHostCache) {
        if (v.exp < now) ipHostCache.delete(k);
        if (ipHostCache.size <= 4000) break;
      }
    }
    return hosting;
  } catch (e) {
    return false;
  }
}
// - Moi HWID: toi da HWID_DAILY_LIMIT luot lay payload/ngay (choi thuong 1 join = 1 luot).
// - Moi IP: toi da IP_NEW_HWID_PER_HOUR HWID moi/gio (chan xoay HWID dump hang loat).
// Memory per-instance (muon chat cross-instance thi dung KV). Vuot -> loi chung nhu moi loi khac.
const HWID_DAILY_LIMIT = 50;
const IP_NEW_HWID_PER_HOUR = 15;
const hwidStats = new Map(); // hwid -> { day, count, firstSeen }
const ipNewHwids = new Map(); // ip -> [timestamps]

function todayStr() {
  return new Date().toISOString().slice(0, 10);
}

function checkHwidThrottle(hwid, ip) {
  const now = Date.now();
  const day = todayStr();
  let st = hwidStats.get(hwid);
  if (!st) {
    const arr = (ipNewHwids.get(ip) || []).filter((t) => now - t < 3600000);
    if (arr.length >= IP_NEW_HWID_PER_HOUR) return false;
    arr.push(now);
    ipNewHwids.set(ip, arr);
    st = { day, count: 0, firstSeen: now };
    hwidStats.set(hwid, st);
  }
  if (st.day !== day) {
    st.day = day;
    st.count = 0;
  }
  st.count += 1;
  if (st.count > HWID_DAILY_LIMIT) return false;
  // Chong tran memory
  if (hwidStats.size > 20000) {
    for (const [k, v] of hwidStats) {
      if (now - v.firstSeen > 86400000) hwidStats.delete(k);
      if (hwidStats.size <= 15000) break;
    }
  }
  return true;
}

const buildLanding = require("./_landing");
const BLACK_PAGE = buildLanding("sodiumsxhub-loader.vercel.app");

function isRoblox(req) {
  // Anti-AI v3: check strict, AI chỉ gửi "Roblox" đơn giản là DIE.
  // Real executor game:HttpGet gửi UA dạng Roblox/WinInet, RobloxStudio/WinInet, Roblox-iOS...
  // Browser/Python/curl gửi kèm Sec-Fetch-*, Accept-Language đầy đủ, hoặc UA lộ python/curl/node.
  const h = (req && req.headers) || {};
  const uaRaw = (h["user-agent"] || "").toString();
  const ua = uaRaw.toLowerCase();
  if (!ua.includes("roblox")) return false;
  // UA giả kiểu "Roblox" trơ trọi (AI curl -A Roblox) -> chặn. Real luôn có / hoặc studio/player/client.
  if (!/roblox(\/|studio|player|client|win|mac|android|ios|uwp|xbox)/i.test(uaRaw)) return false;
  // Thư viện scraping lộ mặt
  if (/python-requests|python\/|curl\/|wget\/|go-http|axios\/|node-fetch|openai|chatgpt|claude|anthropic|bot\/|headless|puppeteer|playwright|scrapy/i.test(uaRaw)) return false;
  // Browser thật luôn gửi Sec-Fetch-*, Roblox HttpGet KHÔNG bao giờ gửi -> có là fake (AI mở bằng browser/fetch).
  if (h["sec-fetch-site"] || h["sec-fetch-mode"] || h["sec-fetch-dest"]) return false;
  // AI hay quên Accept, hoặc gửi Accept kiểu browser đầy đủ + sec-ch-ua
  if (h["sec-ch-ua"] || h["sec-ch-ua-mobile"] || h["sec-ch-ua-platform"]) return false;
  return true;
}

// Tín hiệu AI/bot bổ sung (không chặn cứng 1 mình, dùng để trả bẫy tarpit).
function aiSignals(req) {
  const h = (req && req.headers) || {};
  const ua = ((h["user-agent"]) || "").toString();
  let score = 0;
  if (/python|curl|wget|go-http|axios|node-fetch|openai|chatgpt|gptbot|claude|anthropic|cohere|gemini|bots?[\/\s]/i.test(ua)) score += 3;
  if (h["sec-fetch-site"] || h["sec-ch-ua"]) score += 2;
  const acc = ((h["accept"]) || "").toString();
  if (/text\/html.*application\/.*/i.test(acc)) score += 1; // browser fetch, không phải HttpGet Roblox
  if (!h["user-agent"]) score += 2;
  return score;
}

function getIp(req) {
  const fwd = (req.headers && (req.headers["x-forwarded-for"] || req.headers["x-real-ip"])) || "";
  return fwd.toString().split(",")[0].trim() || "unknown";
}

// Rate-limit nhẹ: tối đa 30 req / 60s / IP cho 2 endpoint này.
function rateLimited(req) {
  const ip = getIp(req);
  const now = Date.now();
  const arr = (ipHits.get(ip) || []).filter((t) => now - t < 60000);
  arr.push(now);
  ipHits.set(ip, arr);
  return arr.length > 30;
}

function getHost(req) {
  const h = (req.headers && (req.headers["x-forwarded-host"] || req.headers.host)) || "sodiumsxhub-loader.vercel.app";
  return h.toString().split(",")[0].trim();
}

function randHex(n) {
  return crypto.randomBytes(n).toString("hex");
}

// Anti-AI: ticket bind theo /24 subnet của IP xin raw -> share ticket sang máy/IP khác là DIE.
// Dùng /24 (thay vì full IP) để user NAT nhảy IP lẻ trong cùng dải vẫn qua, nhưng AI ở datacenter khác dải là chết.
// Stateless (HMAC) nên sống sót cross-instance Vercel, không cần KV.
function getIpSubnet(ip) {
  const s = (ip || "unknown").toString().trim();
  if (s.includes(".")) return s.split(".").slice(0, 3).join("."); // v4 /24
  if (s.includes(":")) return s.split(":").slice(0, 4).join(":").toLowerCase(); // v6 /64 rút gọn
  return "unknown";
}

// ticket = <rand16>.<unix_ts>
function makeTicket() {
  return `${randHex(8)}.${Math.floor(Date.now() / 1000)}`;
}

// v4: sig = HMAC_SHA256(LOADER_SECRET, SCRIPT_ID|ticket|subnet|hwid)
// Ticket bind CẢ subnet IP lẫn HWID đã verify -> đổi hwid (recrack-01) là sig DIE ngay.
// Stateless (HMAC) nên sống sót cross-instance Vercel, không cần KV.
function signTicket(ticket, ip, hwid) {
  const sub = getIpSubnet(ip || "unknown");
  const h = sanitizeHwid(hwid || "unknown");
  return crypto.createHmac("sha256", LOADER_SECRET).update(`${SCRIPT_ID}|${ticket}|${sub}|${h}`).digest("hex");
}

function verifyTicket(ticket, sig, ip, hwid) {
  if (typeof ticket !== "string" || typeof sig !== "string") return false;
  if (!/^[0-9a-f]{16}\.\d{10}$/.test(ticket)) return false;
  if (!/^[0-9a-f]{64}$/.test(sig)) return false;
  const ts = parseInt(ticket.split(".")[1], 10) * 1000;
  if (Math.abs(Date.now() - ts) > TICKET_TTL * 1000) return false;
  const expect = signTicket(ticket, ip || "unknown", hwid || "unknown");
  const a = Buffer.from(expect, "hex");
  const b = Buffer.from(sig, "hex");
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// Proof-of-Work anti-curl: djb2(ticket|nonce) % POW_DIFFICULTY == 0
// Loader Lua phải chạy vòng lặp giải, AI chỉ curl mà không exec Lua là DIE.
// Giữ thuật toán đồng nhất giữa Node và Lua (số học 32-bit).
function powHash(str) {
  let h = 5381;
  for (let i = 0; i < str.length; i++) h = (((h * 33) + str.charCodeAt(i)) >>> 0);
  return h >>> 0;
}

function powVerify(ticket, nonce) {
  const n = (nonce || "").toString();
  if (!/^\d{1,7}$/.test(n)) return false;
  if (parseInt(n, 10) > 5000000) return false;
  return powHash(`${ticket}|${n}`) % POW_DIFFICULTY === 0;
}

// v4: KHÔNG còn đường free cho "HWID đã thấy". seenHwids chỉ giữ để thống kê,
// auth duy nhất là userKey (Turnstile) — vì watermark `-- licensed:HWID` sẽ lộ HWID,
// attacker dùng HWID leak để spoof là bypass ngay nếu còn bypass này.
function isKnownHwid(hwid) {
  return seenHwids.has(hwid);
}

function rememberHwid(hwid) {
  const now = Date.now();
  if (!seenHwids.has(hwid)) seenHwids.set(hwid, now);
  if (seenHwids.size > 20000) {
    for (const [k, v] of seenHwids) {
      if (now - v > 30 * 86400000) seenHwids.delete(k);
      if (seenHwids.size <= 15000) break;
    }
  }
}

function markUsed(ticket) {
  prune();
  if (usedTickets.has(ticket)) return false; // replay
  usedTickets.set(ticket, Date.now() + TICKET_TTL * 1000);
  return true;
}

function prune() {
  const now = Date.now();
  for (const [k, exp] of usedTickets) if (exp < now) usedTickets.delete(k);
}

// Sanitize giống hệt loader Lua :gsub('[^%w%-%.:]','') (%w = alnum + _).
// Server sanitize rồi mới check độ dài -> HWID lạ/Studio vẫn qua, gate chính là ticket HMAC.
function sanitizeHwid(hwid) {
  return (hwid || "").toString().replace(/[^A-Za-z0-9_\-.:]/g, "").slice(0, 80);
}

function validHwid(hwid) {
  const h = sanitizeHwid(hwid);
  return h.length >= 3;
}

function sanitizePlace(place) {
  return (place || "").toString().replace(/[^0-9]/g, "").slice(0, 12);
}

function validPlace(place) {
  // v4: chặn place=0/1 (AI hay dùng để test). PlaceId thật luôn >= 4 chữ số.
  const p = sanitizePlace(place);
  if (!/^\d{4,12}$/.test(p)) return false;
  try {
    if (parseInt(p, 10) < 1000) return false;
  } catch (e) {
    return false;
  }
  return true;
}

function placeAllowed(place) {
  if (!ALLOWED_PLACES) return true;
  const allowed = ALLOWED_PLACES.split(",").map((x) => x.trim()).filter(Boolean);
  return allowed.includes(place);
}

// Key mã hoá payload, bind theo HWID: attacker copy blob sang máy khác là hỏng.
function deriveKey(sig, hwid) {
  return crypto.createHash("sha256").update(`${sig}|${hwid}`).digest(); // 32 bytes
}

function xorCrypt(buf, key) {
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) out[i] = buf[i] ^ key[i % key.length];
  return out;
}

function encryptLua(luaSource, sig, hwid) {
  const key = deriveKey(sig, hwid);
  const blob = xorCrypt(Buffer.from(luaSource, "utf8"), key).toString("base64");
  return { blob, sigHex: sig };
}

function noCache(res) {
  res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
  res.setHeader("Pragma", "no-cache");
  res.setHeader("X-Content-Type-Options", "nosniff");
}

function sendBlack(req, res) {
  // Web thật: khách mới mở bằng browser -> đá sang web fake (giữ nguyên path).
  // Executor (UA Roblox) không bao giờ đi qua đây. Web fake không redirect (tránh loop).
  if (req && !isRoblox(req) && !isFake(req)) {
    const path = (req.url || "/").toString();
    res.setHeader("Location", FAKE_HOST + path);
    return res.status(302).send("");
  }
  res.setHeader("Content-Type", "text/html; charset=utf-8");
  // Web fake hien y chang web that (loader 1 chu b), nhung nut copy chep ban fake (2 chu b)
  // -> mat thay that, chay van an loi.
  if (req && isFake(req)) {
    return res.status(200).send(buildLanding(REAL_HOST, getHost(req)));
  }
  const host = req ? getHost(req) : "sodiumsxhub-loader.vercel.app";
  return res.status(200).send(buildLanding(host));
}

function sendLuaError(res) {
  // Cố tình chung 1 message, không lộ lý do (sai ticket? sai hwid? replay? sai PoW?)
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).send(`error("unauthorized [sodium v4]")`);
}

// Helper cho loader public chưa verify: không cấp ticket, chỉ trả Lua thu HWID
// rồi báo link verify cá nhân. AI cũng nhận cái này -> bắt buộc qua Turnstile browser.
function sendVerifyHelper(res, host) {
  const h = (host || REAL_HOST).toString().replace(/["'<>&\s]/g, "");
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  return res.status(200).send(
`-- sodium v4: verify 1 lan de lay loader ca nhan
local _g=(typeof(gethwid)=='function' and gethwid() or game:GetService('RbxAnalyticsService'):GetClientId())
local _h=tostring(_g or 'unknown'):gsub('[^%w%-%.:]','')
error("verify required: open https://${h}/api/verify?hwid=".._h.." [sodium v4]")
`);
}

// Bẫy AI: trả về Lua nhìn RẤT thật (dài, giống hub obfuscated) nhưng chạy không ra gì.
// AI fetch về sẽ tốn hàng nghìn token phân tích + tưởng đã bypass thành công.
// Real user không bao giờ đi qua đây (chỉ AI/datacenter/sai UA mới dính).
function sendTarpit(res) {
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Cache-Control", "no-store");
  const junk = [];
  junk.push(`-- sodiumhub v2.4.1 (cached build)`);
  junk.push(`local _cfg={version='2.4.1',cdn='edge',region='auto'}`);
  junk.push(`local function _boot()`);
  for (let i = 0; i < 40; i++) {
    junk.push(` local _v${i}=${Math.floor(Math.random() * 999999)} -- sync chunk ${i}`);
  }
  junk.push(` if _cfg.version~='2.4.1' then return end`);
  junk.push(` while true do task.wait(10) end`);
  junk.push(`end`);
  junk.push(`_boot()`);
  // Delay nhẹ 1.5s để scraper hàng loạt bị chậm, user thật không ảnh hưởng (không qua nhánh này).
  return res.status(200).send(junk.join("\n"));
}

module.exports = {
  REQUIRE_KEY,
  SCRIPT_ID,
  LOADER_SECRET,
  ALLOWED_PLACES,
  TURNSTILE_SITE,
  TURNSTILE_SECRET,
  makeUserKey,
  verifyUserKey,
  checkTurnstile,
  FAKE_HOST,
  REAL_HOST,
  isFake,
  TICKET_TTL,
  POW_DIFFICULTY,
  BLACK_PAGE,
  isRoblox,
  aiSignals,
  getIp,
  getIpSubnet,
  rateLimited,
  getHost,
  makeTicket,
  signTicket,
  verifyTicket,
  powHash,
  powVerify,
  isKnownHwid,
  rememberHwid,
  markUsed,
  checkHwidThrottle,
  isDatacenterIP,
  sanitizeHwid,
  validHwid,
  sanitizePlace,
  validPlace,
  placeAllowed,
  deriveKey,
  xorCrypt,
  encryptLua,
  noCache,
  sendBlack,
  sendLuaError,
  sendVerifyHelper,
  sendTarpit,
};
