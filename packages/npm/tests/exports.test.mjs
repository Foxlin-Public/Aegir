import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

// Resolve the advertised package exports, not a hand-written copy or ESM-only test import.
const cjs = createRequire(import.meta.url)("@foxlin_industries/aegir-security");
const esm = await import("@foxlin_industries/aegir-security");
const vectors = JSON.parse(readFileSync(new URL("./crypto-vectors.json", import.meta.url), "utf8"));

for (const [name, sdk] of [["CommonJS", cjs], ["ESM", esm]]) {
  assert.equal(typeof sdk.AegirSecurityClient, "function");
  const calls = [];
  const client = new sdk.AegirSecurityClient({
    baseUrl: "https://example.test/apis", allowTrustedCustomTransport: true,
    fetcher: async (url, init) => {
      calls.push({ url, method: init?.method });
      return new Response(JSON.stringify({ valid: false, status: "SignatureInvalid", detail: null }), {
        status: 200, headers: { "Content-Type": "application/json" }
      });
    }
  });
  const rejected = await client.verifyTransactionReceipt({ transactionId: "fixture", signingKid: "unknown", algorithm: "hybrid-beta1", signature: "AA==" });
  assert.equal(rejected.valid, false);
  assert.equal(calls[0].url, "https://example.test/apis/v1/transactions/receipt/verify");
  assert.equal(calls[0].method, "POST");

  for (const vector of vectors.sha256) {
    assert.equal(sdk.computePayloadDigest(Buffer.from(vector.hex, "hex")), vector.digest);
  }
  for (const [kind, key] of [["Challenge", "challenge"], ["ProofReceipt", "proofReceipt"], ["IdentityToken", "identityToken"]]) {
    const payload = Buffer.from(vectors.historicalKeyless.payloadHex, "hex");
    assert.throws(() => sdk[`sign${kind}Payload`](payload), /unsupported/);
    assert.equal(sdk[`verify${kind}Payload`](payload, Buffer.from(vectors.historicalKeyless[key], "hex")), false);
  }
  assert.deepEqual(sdk.validateSafeEnvelope(sdk.createSafeEnvelope("fixture", "abc")),
    { isValid: true, isAuthenticated: false, reason: "integrity_only" });
  assert.deepEqual(sdk.validateSafeEnvelope(sdk.createSafeEnvelope("fixture", "abc",
    { keyId: "unknown", algorithm: { algorithmId: "ML-DSA-65", hybrid: false }, signatureBytes: Buffer.alloc(3309) })),
    { isValid: false, isAuthenticated: false, reason: "unsupported_signature" });
  console.log(`ok - ${name} package export loads client and preserves R004 fail-closed/digest contracts`);
}

assert.deepEqual(Object.keys(cjs).sort(), Object.keys(esm).sort());
console.log("ok - CommonJS and ESM package exports expose the same runtime symbols");

const compiler = fileURLToPath(new URL("../node_modules/typescript/lib/tsc.js", import.meta.url));
const typed = spawnSync(process.execPath, [compiler, "--noEmit", "--strict", "--skipLibCheck",
  "--target", "ES2022", "--module", "Node16", "--moduleResolution", "Node16",
  fileURLToPath(new URL("./fixtures/consumer.cts", import.meta.url)),
  fileURLToPath(new URL("./fixtures/consumer.mts", import.meta.url))], { encoding: "utf8" });
assert.equal(typed.status, 0, `Package .cts/.mts declaration consumers failed: ${typed.stdout}${typed.stderr}`);
console.log("ok - Node16 TypeScript CommonJS and ESM consumers resolve conditional declarations");

