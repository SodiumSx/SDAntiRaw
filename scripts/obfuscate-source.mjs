// Obfuscate build-time (lớp 2 bên trong source) bằng Clyde.
// Chạy LOCAL trước khi deploy, KHÔNG chạy trên Vercel mỗi request.
//   node scripts/obfuscate-source.mjs [--preset=medium|paranoid|ultra] [--in=source.lua] [--out=api/_code.obf.lua] [--seed=123]
// Khuyên dùng: medium (hub lớn, gọn) hoặc paranoid (hub vừa, có reg-VM).
// ultra chỉ cho script nhỏ (VM-max phình 5-20x, dễ vượt giới hạn response Vercel 4.5MB).
import { readFileSync, writeFileSync, statSync } from "fs";
import { resolve, dirname } from "path";
import { fileURLToPath, pathToFileURL } from "url";

const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, "..");
const DEFAULT_CLYDE = "C:\\Users\\Admin\\Documents\\obflua\\Lua-Obfuscator-Clyde-Protection-main\\Lua-Obfuscator-Clyde-Protection-main\\dist";
const CLYDE = process.env.CLYDE_PATH || DEFAULT_CLYDE;

const args = process.argv.slice(2);
const get = (k, d) => {
  const a = args.find((x) => x.startsWith(k + "="));
  return a ? a.slice(k.length + 1) : d;
};
const preset = get("--preset", "medium");
const inFile = resolve(ROOT, get("--in", "source.lua"));
const outFile = resolve(ROOT, get("--out", "api/_code.obf.lua"));
const seedArg = get("--seed", "");
const seed = seedArg ? parseInt(seedArg, 10) >>> 0 : (((Date.now() & 0xffffff) ^ (Math.floor(Math.random() * 0xffffff))) >>> 0);

if (!["medium", "paranoid", "ultra"].includes(preset)) {
  console.error(`preset phải là medium|paranoid|ultra (nhận "${preset}")`);
  process.exit(1);
}

let src;
try {
  src = readFileSync(inFile, "utf8");
} catch {
  console.error(`Không đọc được ${inFile} — copy source.lua.example thành source.lua trước.`);
  process.exit(1);
}
if (src.length < 10) { console.error("source.lua quá ngắn."); process.exit(1); }
if (src.length > 500000) { console.error("Source > 500KB, chia nhỏ trước khi obfuscate."); process.exit(1); }

const mod = (p) => import(pathToFileURL(`${CLYDE}/${p}`).href);
const { lex } = await mod("lexer/Lexer.js");
const { parse, parseWithErrors } = await mod("parser/Parser.js");
const { obfuscate } = await mod("obfuscator/Obfuscator.js");
const { encodeStrings } = await mod("obfuscator/StringEncoder.js");
const { scrambleControlFlow } = await mod("obfuscator/ControlFlowScrambler.js");
const { flattenControlFlow } = await mod("obfuscator/ControlFlowFlattener.js");
const { poolConstants } = await mod("obfuscator/ConstantArray.js");
const { proxyLocals } = await mod("obfuscator/ProxyLocals.js");
const { proxyGlobals } = await mod("obfuscator/GlobalProxy.js");
const { encryptExpressions } = await mod("obfuscator/ExprEncrypt.js");
const { addAntiDebug } = await mod("obfuscator/AntiDebug.js");
const { addVararg, wrapInFunction } = await mod("obfuscator/FunctionWrap.js");
const { printChunk } = await mod("obfuscator/Printer.js");

const t0 = Date.now();
const { tokens, errors: lexErrors } = lex(src);
if (lexErrors.length > 0) { console.error("Lexer error:", lexErrors.slice(0, 3)); process.exit(1); }
let ast = parse(tokens);

const ultra = preset === "ultra";
const useRegVM = preset === "paranoid" || ultra;

// Lớp 2: rename + encode + scramble + flatten + extra (giống server Clyde, medium trở lên)
ast = poolConstants(ast, { enabled: true, seed });
ast = encodeStrings(ast, { enabled: true, seed });
ast = scrambleControlFlow(ast, { enabled: true, seed, junk: true, numbers: true });
ast = flattenControlFlow(ast, { enabled: true, seed });
if (ultra) ast = scrambleControlFlow(ast, { enabled: true, seed: (seed ^ 0x27d4) >>> 0, junk: true, numbers: true });

let tree = obfuscate(ast, { renameLocals: true, preserveGlobals: true, renameStyle: "confusing", seed });
tree = proxyLocals(tree, { enabled: true });
tree = encryptExpressions(tree, { enabled: true, seed });
tree = addAntiDebug(tree, { enabled: true, seed });
tree = proxyGlobals(tree, { enabled: true, seed });
tree = addVararg(tree, { enabled: true });
tree = wrapInFunction(tree, { enabled: true, layers: 2 });

let output;
if (useRegVM) {
  const { regCompile } = await mod("vm/RegCompiler.js");
  const { generateRegVM } = await mod("vm/reg-vm-gen.js");
  const chunk = regCompile(tree);
  output = generateRegVM(chunk, {
    level: ultra ? "max" : "normal",
    executorGlobals: true,
    polymorphicSeed: seed,
    watermark: false,
  });
} else {
  output = printChunk(tree);
}

// Verify: output phải parse lại được, fail fast thay vì ship code hỏng
{
  const re = lex(output);
  if (re.errors.length > 0) { console.error("Verify failed (lex):", re.errors.slice(0, 3)); process.exit(1); }
  const parsed = parseWithErrors(re.tokens);
  if (parsed.errors.length > 0) { console.error("Verify failed (parse):", parsed.errors.slice(0, 3)); process.exit(1); }
}

writeFileSync(outFile, output, "utf8");
const kb = (n) => (n / 1024).toFixed(1) + "KB";
console.log(`OK preset=${preset} seed=${seed} in=${kb(src.length)} out=${kb(output.length)} ratio=${(output.length / Math.max(1, src.length)).toFixed(2)}x ms=${Date.now() - t0}`);
console.log(` -> ${outFile}`);
try {
  const st = statSync(outFile);
  if (st.size > 3 * 1024 * 1024) console.log("CẢNH BÁO: output > 3MB, cộng base64 transport có thể vượt giới hạn Vercel. Hạ preset xuống medium.");
} catch {}
console.log("Deploy: giữ repo PRIVATE, commit api/_code.obf.lua, KHÔNG commit source.lua.");
