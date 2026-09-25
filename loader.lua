-- SodiumHub public bootstrap v4 (KHONG chứa secret, KHONG chứa logic giải mã).
-- File này public được. Muốn chạy phải verify Turnstile 1 lần để lấy loader cá nhân.
-- Cách dùng: chạy đoạn này trong executor, copy link verify hiện trong console/output rồi mở browser.
-- ĐỔI HOST cho khớp domain Vercel THẬT của bạn:
local HOST = "sodiumsxhub-loader.vercel.app"
loadstring(game:HttpGet("https://" .. HOST .. "/api/raw"))()
