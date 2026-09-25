-- SOURCE THẬT MẪU — copy file này thành source.lua rồi dán hub của bạn vào dưới.
-- source.lua KHÔNG bao giờ commit (đã gitignore). Chỉ file obfuscated api/_code.obf.lua mới deploy.
-- Quy tắc: code Luau thuần, TRÁNH backtick (`) và ${ trong string (kẻo kẹt tooling).
-- Watermark + mã hoá transport do server tự thêm, không cần viết tay.

-- Lớp tự vệ trong source (sẽ bị obfuscate cùng, AI đọc rất mệt):
do
  local ok, placeId = pcall(function() return game.PlaceId end)
  if not ok then return end
  -- ĐIỀN PlaceId game bạn vào đây (ví dụ 1234567). Kẻ cắp mang sang game khác là chết.
  -- local ALLOWED = { [1234567] = true }
  -- if not ALLOWED[placeId] then return end
end

-- Code hub thật của bạn từ đây:
print("sodiumhub")
