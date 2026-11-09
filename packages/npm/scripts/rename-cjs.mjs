import { copyFileSync, existsSync, renameSync, readFileSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";

const jsPath = resolve(process.cwd(), "dist", "cjs", "index.js");
const cjsPath = resolve(process.cwd(), "dist", "cjs", "index.cjs");

if (existsSync(jsPath)) {
  writeFileSync(jsPath, readFileSync(jsPath, "utf8").replaceAll('require("./integration.js")', 'require("./integration.cjs")').replaceAll('require("./legacy.js")', 'require("./legacy.cjs")'));
  renameSync(jsPath, cjsPath);
}

const integrationJs = resolve(process.cwd(), "dist", "cjs", "integration.js");
if (existsSync(integrationJs)) renameSync(integrationJs, resolve(process.cwd(), "dist", "cjs", "integration.cjs"));

// Node16 TypeScript consumers distinguish CommonJS declarations by their .d.cts extension.
const declarationPath = resolve(process.cwd(), "dist", "types", "index.d.ts");
copyFileSync(declarationPath, resolve(process.cwd(), "dist", "types", "index.d.cts"));
const commonTypes = resolve(process.cwd(), "dist", "types", "index.d.cts");
writeFileSync(commonTypes, readFileSync(commonTypes, "utf8").replaceAll('"./integration.js"', '"./integration.cjs"'));
copyFileSync(resolve(process.cwd(), "dist", "types", "integration.d.ts"), resolve(process.cwd(), "dist", "types", "integration.d.cts"));

const legacyJs = resolve(process.cwd(), "dist", "cjs", "legacy.js");
if (existsSync(legacyJs)) renameSync(legacyJs, resolve(process.cwd(), "dist", "cjs", "legacy.cjs"));
writeFileSync(commonTypes, readFileSync(commonTypes, "utf8").replaceAll('"./legacy.js"', '"./legacy.cjs"'));
copyFileSync(resolve(process.cwd(), "dist", "types", "legacy.d.ts"), resolve(process.cwd(), "dist", "types", "legacy.d.cts"));
