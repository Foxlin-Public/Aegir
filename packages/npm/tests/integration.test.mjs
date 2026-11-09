// Copyright Foxlin Industries. Native adversarial SDK tests, not real-server parity certification.
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { AegirIntegrationClient, FileAuthorizationJournal } from "../dist/esm/index.js";
import { createRequire, syncBuiltinESMExports } from "node:module";
import { EventEmitter } from "node:events";
let passed = 0;
async function test(name, action) { await action(); passed++; console.log("ok - integration " + name); }
const dir = mkdtempSync(join(tmpdir(), "aegir-native-integration-"));
let seq = 0;
const journal = () => new FileAuthorizationJournal(join(dir, String(++seq) + ".json"), "synthetic-stream");
const evt = (id, version = 1, type = "granted", tx = "tx-shared") => ({
  protocolVersion: 1, transactionId: tx, eventId: id, groupId: "app-group-alias",
  userId: "app-subject-alias", eventType: type, groupVersion: version
});
const snap = version => ({ snapshotId: "snapshot", groups: [{ groupId: "app-group-alias", groupVersion: version, subjects: [] }] });
const permit = () => ({ isAuthorized: true, reason: "authorized", applicationSubjectId: "app-subject-alias",
  authorizationEpoch: 0, effectiveGroupIds: ["app-group-alias"], permissions: ["read", "write"] });
function client(store) { return new AegirIntegrationClient({ apiBaseUrl: "https://example.invalid/apis/",
  webBaseUrl: "https://example.invalid/", applicationCredential: "synthetic-key", organizationId: "synthetic-org",
  applicationId: "synthetic-app", journal: store, timeoutMs: 100 }); }
try {
await test("atomic event receipt and restart", () => {
  const path = join(dir, "restart.json"); let s = new FileAuthorizationJournal(path, "binding");
  assert.deepEqual(s.apply([evt("one")]), { newEffects: 1, requiresSnapshot: false }); s.setConnected(true); s.close();
  s = new FileAuthorizationJournal(path, "binding"); assert.equal(s.inspect().connected, false);
  assert.equal(s.inspect().effects, 1); assert.equal(s.apply([evt("one")]).newEffects, 0); s.close();
});
await test("same transaction distinct event identities", () => {
  const s = journal(); assert.equal(s.apply([evt("a"), evt("b")]).newEffects, 2); assert.equal(s.inspect().receipts, 2); s.close();
});
await test("late grant never supersedes revocation", () => {
  const s = journal(); s.apply([evt("a"), evt("b", 2, "revoked")]); assert.equal(s.apply([evt("late", 1)]).newEffects, 0);
  assert.equal(s.inspect().versions["app-group-alias"], 2); s.close();
});
await test("gap rolls back whole batch", () => {
  const s = journal(); assert.equal(s.apply([evt("a"), evt("gap", 4)]).requiresSnapshot, true);
  assert.equal(s.inspect().receipts, 0); s.close();
});
await test("unknown type rolls back whole batch", () => {
  const s = journal(); assert.equal(s.apply([evt("a"), evt("future", 2, "futureGrant")]).requiresSnapshot, true);
  assert.equal(s.inspect().effects, 0); s.close();
});
await test("unsupported protocol fails closed", () => {
  const s = journal(); assert.throws(() => s.apply([{ ...evt("a"), protocolVersion: 2 }]), /unsupported_event_protocol/); s.close();
});
await test("event privacy extra fields rejected", () => {
  const s = journal(); assert.throws(() => s.apply([{ ...evt("a"), email: "synthetic@example.invalid" }]), /unsupported_event_protocol/); s.close();
});
await test("event identity conflict rejected atomically", () => {
  const s = journal(); s.apply([evt("a")]); assert.throws(() => s.apply([evt("b", 2), evt("a", 1, "revoked")]), /event_identity_conflict/);
  assert.equal(s.inspect().effects, 1); s.close();
});
await test("snapshot rollback rejected", () => {
  const s = journal(); s.applySnapshot(snap(5)); assert.throws(() => s.applySnapshot(snap(4)), /snapshot_rollback/); s.close();
});
await test("single writer lock and binding prevent substitution", () => {
  const path = join(dir, "lock.json"); const s = new FileAuthorizationJournal(path, "binding");
  assert.throws(() => new FileAuthorizationJournal(path, "binding"), /journal_locked/); s.close();
  assert.throws(() => new FileAuthorizationJournal(path, "other"), /journal_binding_mismatch/);
});
await test("unsafe URL and nonloopback pin rejected", () => {
  const s = journal();
  for (const url of ["http://example.invalid/", "https://user:secret@example.invalid/", "https://example.invalid/?q=x",
    "https://example.invalid/#fragment", "https://example.invalid/no-trailing", "https://example.invalid/%2e/"]) {
    assert.throws(() => new AegirIntegrationClient({ apiBaseUrl: url, webBaseUrl: "https://example.invalid/", applicationCredential: "x", organizationId: "org", applicationId: "app", journal: s }), /invalid_configuration/);
  }
  assert.throws(() => new AegirIntegrationClient({ apiBaseUrl: "https://example.invalid/", webBaseUrl: "https://example.invalid/",
    applicationCredential: "x", organizationId: "org", applicationId: "app", journal: s, certificateSha256: "a".repeat(64) }), /invalid_configuration/); s.close();
});
await test("startup and unsupported operation deny without contacting authority", async () => {
  const s = journal(), c = client(s);
  assert.equal((await c.authorize("ticket", "read")).isAuthorized, false);
  assert.equal((await c.authorize("ticket", "delete")).reason, "unsupported_operation"); c.close(); s.close();
});
await test("contradictory reason and status prevent callback", async () => {
  for (const response of [{ status: 403, value: permit() }, { status: 200, value: { ...permit(), reason: "license_required" } },
    { status: 200, value: { ...permit(), permissions: ["read"] } }, { status: 200, value: { ...permit(), applicationSubjectId: null } }]) {
    const s = journal(), c = client(s); c.connected = true; c.api.request = async () => response; let effects = 0;
    assert.equal((await c.execute("ticket", "write", () => effects++)).isAuthorized, false); assert.equal(effects, 0); c.close(); s.close();
  }
});
await test("revalidation denies effect after preparation revokes", async () => {
  const s = journal(), c = client(s); c.connected = true; let reads = 0, effects = 0;
  c.api.request = async () => ++reads === 1 ? { status: 200, value: permit() } :
    { status: 403, value: { ...permit(), isAuthorized: false, reason: "license_required" } };
  assert.equal((await c.execute("ticket", "write", () => effects++, () => {})).isAuthorized, false);
  assert.equal(reads, 2); assert.equal(effects, 0); c.close(); s.close();
});
await test("dispose during preparation prevents callback", async () => {
  const s = journal(), c = client(s); c.connected = true; c.api.request = async () => ({ status: 200, value: permit() }); let effects = 0;
  await assert.rejects(c.execute("ticket", "write", () => effects++, async () => c.close()), /disposed/);
  assert.equal(effects, 0); s.close();
});
await test("dispose during reconnect never reconnects", async () => {
  const s = journal(), c = client(s);
  c.api.request = async () => { c.close(); return { status: 200, value: { deliveryId: null, events: [], requiresSnapshot: false, reason: null, retryAfterSeconds: 1 } }; };
  await assert.rejects(c.reconnect(), /disposed/); assert.equal(s.inspect().connected, false); s.close();
});
await test("healthy polling preserves established connection", async () => {
  const s = journal(), c = client(s); c.connected = true; s.setConnected(true);
  c.api.request = async () => ({ status: 200, value: { deliveryId: null, events: [], requiresSnapshot: false, reason: null, retryAfterSeconds: 1 } });
  assert.equal((await c.poll()).connected, true); assert.equal(s.inspect().connected, true); c.close(); s.close();
});
await test("cancelled check never executes callback", async () => {
  const s = journal(), c = client(s); c.connected = true; const abort = new AbortController(); abort.abort(); let effects = 0;
  await assert.rejects(c.execute("ticket", "write", () => effects++, undefined, abort.signal), /cancelled/);
  assert.equal(effects, 0); c.close(); s.close();
});
await test("duplicate JSON receipt keys rejected on recovery", () => {
  const path = join(dir, "duplicate.json"); const s = new FileAuthorizationJournal(path, "binding"); s.close();
  const raw = readFileSync(path, "utf8").replace('"connected":false', '"connected":true,"connected":false');
  writeFileSync(path, raw); assert.throws(() => new FileAuthorizationJournal(path, "binding"), /invalid_server_response/);
});
await test("absent group keeps version highwater", () => {
  const s = journal(); s.applySnapshot(snap(5)); s.applySnapshot({ snapshotId: "empty", groups: [] });
  assert.throws(() => s.applySnapshot(snap(4)), /snapshot_rollback/); s.close();
});
await test("deep JSON rejected within bounded parse", () => {
  const path = join(dir, "deep.json"); writeFileSync(path, "[".repeat(40) + "0" + "]".repeat(40));
  assert.throws(() => new FileAuthorizationJournal(path, "binding"), /invalid_server_response/);
});
await test("expired or subjectless authentication session rejected", async () => {
  const s = journal(), c = client(s);
  for (const extra of [{ subjectId: "" }, { expiresAtUtc: "2000-01-01T00:00:00Z" }]) {
    c.web.request = async () => ({ status: 200, value: { accessToken: "private-ticket", subjectId: "synthetic",
      organizationId: "synthetic-org", applicationId: "synthetic-app", expiresAtUtc: "2999-01-01T00:00:00Z", authorizationEpoch: 0, ...extra } });
    await assert.rejects(c.authenticate("synthetic", "synthetic-password"), /invalid_server_response/);
  }
  c.close(); s.close();
});
await test("optional outer extension preserves exact approved authority", async () => {
  const s = journal(), c = client(s); c.connected = true; let effects = 0;
  c.api.request = async () => ({ status: 200, value: { ...permit(), futureOptional: "ignored" } });
  assert.equal((await c.execute("ticket", "write", () => effects++)).isAuthorized, true); assert.equal(effects, 1);
  c.web.request = async () => ({ status: 200, value: { accessToken: "private-ticket", subjectId: "synthetic",
    organizationId: "synthetic-org", applicationId: "synthetic-app", expiresAtUtc: "2999-01-01T00:00:00Z", authorizationEpoch: 0, futureOptional: "ignored" } });
  assert.equal((await c.authenticate("synthetic", "synthetic-password")).organizationId, "synthetic-org"); c.close(); s.close();
});
await test("owned transport rejects misleading MIME before accepting session", async () => {
  const require = createRequire(import.meta.url), https = require("node:https"), original = https.request;
  let mime;
  try {
    https.request = (_url, _options, callback) => {
      const request = new EventEmitter(); request.write = () => {}; request.destroy = () => {};
      request.end = () => queueMicrotask(() => {
        const response = new EventEmitter(); response.statusCode = 200; response.headers = { "content-type": mime };
        response.destroy = () => {}; callback(response);
        response.emit("data", Buffer.from(JSON.stringify({ accessToken: "private-ticket", subjectId: "synthetic",
          organizationId: "synthetic-org", applicationId: "synthetic-app", expiresAtUtc: "2999-01-01T00:00:00Z", authorizationEpoch: 0 })));
        response.emit("end");
      }); return request;
    };
    syncBuiltinESMExports();
    const s = journal(), c = client(s);
    try {
      for (mime of ["application/jsonp", "text/plain; note=application/json"]) {
        await assert.rejects(c.authenticate("synthetic", "synthetic-password"), /invalid_server_response/);
      }
      mime = "Application/JSON; charset=utf-8";
      assert.equal((await c.authenticate("synthetic", "synthetic-password")).applicationId, "synthetic-app");
    } finally { c.close(); s.close(); }
  } finally { https.request = original; syncBuiltinESMExports(); }
});
console.log(JSON.stringify({ suite: "integration-native", passed, failed: 0 }));
} finally {
  const full = resolve(dir), prefix = resolve(tmpdir()) + (process.platform === "win32" ? "\\" : "/");
  if (!full.startsWith(prefix)) throw new Error("test cleanup containment");
  rmSync(full, { recursive: true, force: true });
}

