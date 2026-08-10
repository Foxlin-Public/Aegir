// End-to-end flow against a running Aegir API host.
//
// This is NOT part of `npm test`. It talks to a real host and a real database, which the unit
// suite must never do. Run it against a development deployment:
//
//   AEGIR_BASE_URL=http://127.0.0.1:5199/apis \
//   AEGIR_DEVELOPER_KEY=devkey_x:secret \
//   node ./tests/live-flow.mjs
//
// It exercises the capabilities Beta-1 claims, in the order a real integrator would:
// register two agents, open a transaction, protect a message from one to the other, prove the
// wrong agent cannot open it, prove it cannot be moved to another transaction, and pull the
// signed receipt.

import assert from "node:assert/strict";

import { AegirSecurityClient, AegirSecurityError } from "../dist/esm/index.js";

const baseUrl = process.env.AEGIR_BASE_URL;
const developerKey = process.env.AEGIR_DEVELOPER_KEY;

if (!baseUrl || !developerKey) {
  console.error("Set AEGIR_BASE_URL and AEGIR_DEVELOPER_KEY to run the live flow.");
  process.exit(2);
}

const step = (name) => console.log(`\n== ${name}`);
const suffix = Date.now();

const developer = new AegirSecurityClient({ baseUrl, developerKey });

step("developer token");
const developerToken = await developer.getToken();
assert.equal(developerToken.token_type, "Bearer");
console.log(`   scopes: ${developerToken.scopes.join(" ")}`);

step("register two agents");
const alpha = await developer.registerAgent({
  displayName: `live-alpha-${suffix}`,
  scopes: ["agent:message", "transaction:write"]
});
const beta = await developer.registerAgent({
  displayName: `live-beta-${suffix}`,
  scopes: ["agent:message", "transaction:write"]
});
const gamma = await developer.registerAgent({
  displayName: `live-gamma-${suffix}`,
  scopes: ["agent:message", "transaction:write"]
});
console.log(`   alpha=${alpha.agent.agentId} beta=${beta.agent.agentId}`);

// Each agent authenticates as itself. The developer key is not reused below this point.
const alphaClient = new AegirSecurityClient({ baseUrl });
await alphaClient.useAgentKey(alpha.agentKey);

const betaClient = new AegirSecurityClient({ baseUrl });
await betaClient.useAgentKey(beta.agentKey);

const gammaClient = new AegirSecurityClient({ baseUrl });
await gammaClient.useAgentKey(gamma.agentKey);

step("open a transaction before the protected operation");
const transaction = await alphaClient.createTransaction({ declaredAction: "agent.message.send" });
assert.match(transaction.transactionId, /^AGTX-[0-9A-F]{32}$/);
assert.equal(transaction.status, "Created");
assert.equal(transaction.agentPrincipalId, alpha.agent.agentId);
console.log(`   ${transaction.transactionId}`);

step("protect a payload from alpha to beta");
const secret = JSON.stringify({ finding: "CVE-2026-0001", severity: "high" });
const message = await alphaClient.sendAgentMessage({
  transactionId: transaction.transactionId,
  recipientAgentId: beta.agent.agentId,
  action: "agent.finding.share",
  payload: Buffer.from(secret, "utf8").toString("base64")
});

assert.equal(message.envelope.header.kemAlgorithm, "ML-KEM-768");
assert.equal(message.envelope.header.signatureAlgorithm, "ML-DSA-65");
assert.equal(message.envelope.header.aeadAlgorithm, "AES-256-GCM");
assert.equal(message.envelope.header.transactionId, transaction.transactionId);

// The payload must not be recoverable from the wire form.
assert.ok(!JSON.stringify(message).includes("CVE-2026-0001"));
console.log(`   ${message.envelope.header.version} envelope, ciphertext ${message.envelope.ciphertext.length} b64 chars`);

step("the wrong agent cannot open it");
await assertRefused(
  () => gammaClient.receiveAgentMessage(message),
  403,
  "gamma opened a message addressed to beta"
);

step("it cannot be moved to another transaction");
const otherTransaction = await alphaClient.createTransaction({ declaredAction: "agent.message.send" });
const moved = {
  transactionId: otherTransaction.transactionId,
  envelope: {
    ...message.envelope,
    header: { ...message.envelope.header, transactionId: otherTransaction.transactionId }
  }
};
await assertRefused(
  () => betaClient.receiveAgentMessage(moved),
  403,
  "an envelope minted for one transaction was accepted under another"
);

step("the addressee opens it");
const delivery = await betaClient.receiveAgentMessage(message);
assert.equal(delivery.senderAgentId, alpha.agent.agentId);
assert.equal(delivery.action, "agent.finding.share");
assert.equal(Buffer.from(delivery.payload, "base64").toString("utf8"), secret);
console.log(`   delivered from ${delivery.senderAgentId}`);

step("replaying it fails");
await assertRefused(
  () => betaClient.receiveAgentMessage(message),
  403,
  "a protected message was accepted twice"
);

step("the transaction trail and signed receipt");
const events = await developer.getTransactionEvents(transaction.transactionId);
console.log(`   ${events.map((entry) => entry.eventType).join(" -> ")}`);
assert.deepEqual(
  events.map((entry) => entry.eventType),
  ["transaction.created", "transaction.authorized", "transaction.in_progress", "transaction.completed"]
);

// No event may carry the payload. Aegir proves the exchange, it does not retain it.
for (const entry of events) {
  assert.ok(!(entry.detail ?? "").includes("CVE-2026-0001"));
}

const receipt = await developer.getTransactionReceipt(transaction.transactionId);
assert.equal(receipt.algorithm, "ML-DSA-65");
assert.equal(receipt.transactionId, transaction.transactionId);
assert.ok(!JSON.stringify(receipt).includes("CVE-2026-0001"));

const verification = await developer.verifyTransactionReceipt(receipt);
assert.equal(verification.valid, true, `receipt did not verify: ${verification.status}`);
console.log(`   receipt ${receipt.signingKid} verified: ${verification.status}`);

step("a tampered receipt does not verify");
const tampered = { ...receipt, declaredAction: "agent.credential.export" };
const tamperedResult = await developer.verifyTransactionReceipt(tampered);
assert.equal(tamperedResult.valid, false);
console.log(`   tampered receipt rejected: ${tamperedResult.status}`);

console.log("\nlive flow ok");

async function assertRefused(run, expectedStatus, failureMessage) {
  try {
    await run();
  } catch (error) {
    assert.ok(error instanceof AegirSecurityError, `unexpected error: ${error}`);
    assert.equal(error.status, expectedStatus, `expected ${expectedStatus}, got ${error.status}`);
    console.log(`   refused with ${error.status} ${error.code}`);
    return;
  }

  throw new Error(failureMessage);
}
