// Copyright Foxlin Industries. Additive, unreleased protocol-v1 developer integration.
import { request as httpsRequest, Agent } from "node:https";
import { connect as tlsConnect, TLSSocket } from "node:tls";
import { createHash, timingSafeEqual, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync, openSync, closeSync, fsyncSync, renameSync, unlinkSync, existsSync, lstatSync } from "node:fs";
import { resolve, dirname } from "node:path";

export class AegirIntegrationError extends Error {
  constructor(public readonly code: string) { super(code); this.name = "AegirIntegrationError"; }
}
export class AegirMfaRequired extends AegirIntegrationError {
  constructor(public readonly challengeId: string) { super("mfa_required"); }
}
export type AegirApplicationOperation = "read" | "write";
export interface AuthorizationNotification {
  protocolVersion: 1; transactionId: string; eventId: string; groupId: string;
  userId: string | null; eventType: string; groupVersion: number;
}
export interface AuthorizationConsumerSnapshot {
  snapshotId: string; groups: { groupId: string; groupVersion: number;
    subjects: { userId: string; allowed: boolean; authorizationEpoch: number }[] }[];
}
export interface AuthorizationProtectedDecision {
  isAuthorized: boolean; reason: string; applicationSubjectId: string | null;
  authorizationEpoch: number; effectiveGroupIds: string[]; permissions: string[];
}
export interface AuthorizationJournalState {
  connected: boolean; receipts: number; effects: number; versions: Record<string, number>; eventIds: string[];
}
export interface AuthorizationJournal {
  /** All receipt/version/invalidation changes MUST commit in one durable transaction. */
  apply(events: AuthorizationNotification[]): { newEffects: number; requiresSnapshot: boolean };
  applySnapshot(snapshot: AuthorizationConsumerSnapshot): void;
  setConnected(connected: boolean): void;
  inspect(): AuthorizationJournalState;
  close(): void;
}
export const AUTHORIZATION_EVENT_TYPES = Object.freeze([
  "granted", "revoked", "adminGranted", "adminRevoked", "permissionChanged", "licenseGranted",
  "licenseRevoked", "membershipChanged", "suspended", "restored", "groupPolicyChanged"
]);
const fields = ["protocolVersion", "transactionId", "eventId", "groupId", "userId", "eventType", "groupVersion"].sort();
const text = (v: unknown, limit = 512): v is string => typeof v === "string" && v.trim().length > 0 && v.length <= limit;
const integer = (v: unknown, min = 0): v is number => Number.isSafeInteger(v) && (v as number) >= min;
function object(v: unknown): Record<string, any> {
  if (!v || typeof v !== "object" || Array.isArray(v)) throw new AegirIntegrationError("invalid_server_response");
  return v as Record<string, any>;
}
function event(v: unknown): AuthorizationNotification {
  const e = object(v);
  if (JSON.stringify(Object.keys(e).sort()) !== JSON.stringify(fields) || e.protocolVersion !== 1)
    throw new AegirIntegrationError("unsupported_event_protocol");
  if (!["transactionId", "eventId", "groupId", "eventType"].every(k => text(e[k])) ||
      !integer(e.groupVersion, 1) || (e.userId !== null && !text(e.userId)))
    throw new AegirIntegrationError("invalid_server_response");
  return e as AuthorizationNotification;
}
function snapshot(v: unknown): AuthorizationConsumerSnapshot {
  const s = object(v);
  if (!text(s.snapshotId) || !Array.isArray(s.groups) || s.groups.length > 100)
    throw new AegirIntegrationError("invalid_server_response");
  const groups = new Set<string>(); let total = 0;
  for (const value of s.groups) {
    const g = object(value);
    if (!text(g.groupId) || groups.has(g.groupId) || !integer(g.groupVersion) || !Array.isArray(g.subjects))
      throw new AegirIntegrationError("invalid_server_response");
    groups.add(g.groupId); const subjects = new Set<string>(); total += g.subjects.length;
    for (const value of g.subjects) {
      const u = object(value);
      if (!text(u.userId) || subjects.has(u.userId) || typeof u.allowed !== "boolean" || !integer(u.authorizationEpoch))
        throw new AegirIntegrationError("invalid_server_response");
      subjects.add(u.userId);
    }
  }
  if (total > 2000) throw new AegirIntegrationError("invalid_server_response");
  return s as AuthorizationConsumerSnapshot;
}
type FileState = { format: 1; binding: string; connected: boolean;
  receipts: Record<string, AuthorizationNotification>; versions: Record<string, number>;
  effects: Record<string, string>; subjects: Record<string, string[]> };
const own = (v: object, k: string) => Object.prototype.hasOwnProperty.call(v, k);
const canonicalEvent = (e: AuthorizationNotification) => JSON.stringify(fields.map(k => [k, (e as any)[k]]));

// JSON permits syntactic duplicate object keys; authority responses must not.
// Validate keys on the original bounded text before ordinary JSON decoding.
function strictJson(source: string): any {
  let i = 0;
  const space = () => { while (/\s/.test(source[i] ?? "") && i < source.length) i++; };
  const string = () => {
    const start = i++;
    while (i < source.length) {
      if (source[i] === "\\") { i += 2; continue; }
      if (source[i++] === '"') return JSON.parse(source.slice(start, i)) as string;
    }
    throw new AegirIntegrationError("invalid_server_response");
  };
  const value = (depth = 0): void => {
    if (depth > 32) throw new AegirIntegrationError("invalid_server_response");
    space();
    if (source[i] === "{") {
      i++; space(); const keys = new Set<string>();
      if (source[i] === "}") { i++; return; }
      while (i < source.length) {
        space(); if (source[i] !== '"') throw new AegirIntegrationError("invalid_server_response");
        const key = string(); if (keys.has(key)) throw new AegirIntegrationError("invalid_server_response"); keys.add(key);
        space(); if (source[i++] !== ":") throw new AegirIntegrationError("invalid_server_response"); value(depth + 1); space();
        const end = source[i++]; if (end === "}") return; if (end !== ",") throw new AegirIntegrationError("invalid_server_response");
      }
    } else if (source[i] === "[") {
      i++; space(); if (source[i] === "]") { i++; return; }
      while (i < source.length) { value(depth + 1); space(); const end = source[i++]; if (end === "]") return; if (end !== ",") throw new AegirIntegrationError("invalid_server_response"); }
    } else if (source[i] === '"') { string(); return; }
    else {
      const start = i; while (i < source.length && !/[\s,\]}]/.test(source[i])) i++;
      if (start === i) throw new AegirIntegrationError("invalid_server_response"); JSON.parse(source.slice(start, i)); return;
    }
    throw new AegirIntegrationError("invalid_server_response");
  };
  value(); space(); if (i !== source.length) throw new AegirIntegrationError("invalid_server_response"); return JSON.parse(source);
}

/** Atomic local, single-writer journal. A crash leaves a lock requiring operator recovery.
 * Replace with an application-owned transactional adapter for distributed/multiwriter hosts.
 * File contains scoped aliases and receipts, never credentials. Startup always disconnects.
 */
export class FileAuthorizationJournal implements AuthorizationJournal {
  private state: FileState; private lock: number; private closed = false; private readonly path: string;
  constructor(path: string, binding: string) {
    if (!text(binding, 2048)) throw new AegirIntegrationError("invalid_configuration");
    this.path = resolve(path);
    if (existsSync(this.path) && lstatSync(this.path).isSymbolicLink())
      throw new AegirIntegrationError("unsafe_journal_path");
    try { this.lock = openSync(this.path + ".lock", "wx", 0o600); }
    catch { throw new AegirIntegrationError("journal_locked"); }
    try {
      if (existsSync(this.path)) {
        const source = readFileSync(this.path);
        if (source.length > 32 * 1024 * 1024) throw new AegirIntegrationError("journal_capacity");
        const loaded = object(strictJson(source.toString("utf8")));
        if (loaded.format !== 1 || loaded.binding !== binding) throw new AegirIntegrationError("journal_binding_mismatch");
        if (typeof loaded.connected !== "boolean") throw new AegirIntegrationError("invalid_journal");
        for (const key of ["receipts", "versions", "effects", "subjects"]) object(loaded[key]);
        for (const [id, value] of Object.entries(loaded.receipts)) if (event(value).eventId !== id) throw new AegirIntegrationError("invalid_journal");
        for (const version of Object.values(loaded.versions)) if (!integer(version)) throw new AegirIntegrationError("invalid_journal");
        this.state = loaded as FileState;
      } else {
        this.state = { format: 1, binding, connected: false, receipts: {}, versions: {}, effects: {}, subjects: {} };
      }
      this.commit({ ...this.state, connected: false });
    } catch (error) {
      closeSync(this.lock); unlinkSync(this.path + ".lock");
      if (error instanceof AegirIntegrationError) throw error;
      throw new AegirIntegrationError("invalid_journal");
    }
  }
  private ready() { if (this.closed) throw new AegirIntegrationError("disposed"); }
  private commit(next: FileState) {
    this.ready();
    const encoded = JSON.stringify(next);
    if (Buffer.byteLength(encoded) > 32 * 1024 * 1024 || Object.keys(next.receipts).length > 100000)
      throw new AegirIntegrationError("journal_capacity");
    const tmp = this.path + "." + randomUUID() + ".tmp";
    let fd: number | undefined;
    try {
      fd = openSync(tmp, "wx", 0o600); writeFileSync(fd, encoded); fsyncSync(fd); closeSync(fd); fd = undefined;
      renameSync(tmp, this.path);
      // Directory fsync is available on Unix. Windows FlushFileBuffers above plus rename
      // supplies the tested local process-crash boundary; power-loss qualification is separate.
      if (process.platform !== "win32") { const dir = openSync(dirname(this.path), "r"); try { fsyncSync(dir); } finally { closeSync(dir); } }
      this.state = next;
    } finally { if (fd !== undefined) closeSync(fd); if (existsSync(tmp)) unlinkSync(tmp); }
  }
  setConnected(connected: boolean) { this.commit({ ...this.state, connected }); }
  apply(events: AuthorizationNotification[]) {
    this.ready();
    if (!Array.isArray(events) || events.length > 100) throw new AegirIntegrationError("invalid_server_response");
    const parsed = events.map(event);
    if (parsed.some(e => !AUTHORIZATION_EVENT_TYPES.includes(e.eventType))) return { newEffects: 0, requiresSnapshot: true };
    const next = structuredClone(this.state); let effects = 0;
    for (const e of parsed) {
      if (own(next.receipts, e.eventId)) {
        if (canonicalEvent(next.receipts[e.eventId]) !== canonicalEvent(e)) throw new AegirIntegrationError("event_identity_conflict");
        continue;
      }
      const prior = own(next.versions, e.groupId) ? next.versions[e.groupId] : 0;
      if (e.groupVersion > prior + 1) return { newEffects: 0, requiresSnapshot: true };
      Object.defineProperty(next.receipts, e.eventId, { value: e, enumerable: true, configurable: true, writable: true });
      if (e.groupVersion < prior) continue;
      Object.defineProperty(next.versions, e.groupId, { value: Math.max(prior, e.groupVersion), enumerable: true, configurable: true, writable: true });
      Object.defineProperty(next.effects, e.eventId, { value: e.eventType, enumerable: true, configurable: true, writable: true });
      delete next.subjects[e.groupId]; effects++;
    }
    this.commit(next); return { newEffects: effects, requiresSnapshot: false };
  }
  applySnapshot(value: AuthorizationConsumerSnapshot) {
    const s = snapshot(value); const next = structuredClone(this.state);
    for (const g of s.groups) {
      if (own(next.versions, g.groupId) && g.groupVersion < next.versions[g.groupId])
        throw new AegirIntegrationError("snapshot_rollback");
    }
    // Retain high-water versions for absent groups; only live projections clear.
    next.subjects = {};
    for (const g of s.groups) {
      Object.defineProperty(next.versions, g.groupId, { value: g.groupVersion, enumerable: true, configurable: true, writable: true });
      Object.defineProperty(next.subjects, g.groupId, { value: g.subjects.filter(u => u.allowed).map(u => u.userId), enumerable: true, configurable: true, writable: true });
    }
    this.commit(next);
  }
  inspect(): AuthorizationJournalState {
    this.ready(); return { connected: this.state.connected, receipts: Object.keys(this.state.receipts).length,
      effects: Object.keys(this.state.effects).length, versions: { ...this.state.versions }, eventIds: Object.keys(this.state.receipts).sort() };
  }
  close() {
    if (this.closed) return;
    try { this.setConnected(false); } finally { this.closed = true; closeSync(this.lock); unlinkSync(this.path + ".lock"); }
  }
}
class SafeHttpsTransport {
  private readonly base: URL; private readonly agent: Agent; private disposed = false;
  private readonly active = new Set<ReturnType<typeof httpsRequest>>();
  constructor(baseUrl: string, certificateSha256: string | undefined, private readonly timeoutMs: number) {
    if (typeof baseUrl !== "string" || /[\\\r\n\t%]/.test(baseUrl)) throw new AegirIntegrationError("invalid_configuration");
    try { this.base = new URL(baseUrl); } catch { throw new AegirIntegrationError("invalid_configuration"); }
    if (this.base.protocol !== "https:" || this.base.username || this.base.password || this.base.search ||
        this.base.hash || !this.base.pathname.endsWith("/")) throw new AegirIntegrationError("invalid_configuration");
    this.agent = new Agent({ keepAlive: false });
    if (certificateSha256 !== undefined) {
      if (!["localhost", "127.0.0.1", "[::1]"].includes(this.base.hostname) || !/^[a-fA-F0-9]{64}$/.test(certificateSha256))
        throw new AegirIntegrationError("invalid_configuration");
      const pin = Buffer.from(certificateSha256, "hex");
      // Only return the connected TLS socket to HTTP after the exact pin passes;
      // credentials cannot be written before this verification. No global trust changes.
      (this.agent as any).createConnection = (options: any, callback: (err: Error | null, socket?: TLSSocket) => void) => {
        const socket = tlsConnect({ ...options, rejectUnauthorized: false });
        let returned = false;
        socket.once("error", error => { if (!returned) { returned = true; callback(error); } });
        socket.once("secureConnect", () => {
          const raw = socket.getPeerCertificate().raw;
          const actual = raw ? createHash("sha256").update(raw).digest() : Buffer.alloc(0);
          if (actual.length !== pin.length || !timingSafeEqual(actual, pin)) {
            if (!returned) { returned = true; callback(new AegirIntegrationError("certificate_pin_mismatch")); }
            socket.destroy(); return;
          }
          if (!returned) { returned = true; callback(null, socket); }
        });
        return undefined;
      };
    }
  }
  async request(path: string, body?: object, credential?: string, signal?: AbortSignal): Promise<{ status: number; value: any }> {
    if (this.disposed) throw new AegirIntegrationError("disposed");
    if (signal?.aborted) throw new AegirIntegrationError("cancelled");
    return new Promise((resolve, reject) => {
      const headers: Record<string, string> = { Accept: "application/json" };
      const data = body === undefined ? undefined : JSON.stringify(body);
      if (credential) headers["X-Aegir-Application-Key"] = credential;
      if (data !== undefined) { headers["Content-Type"] = "application/json"; headers["Content-Length"] = String(Buffer.byteLength(data)); }
      let done = false;
      const req = httpsRequest(new URL(path, this.base), { method: data === undefined ? "GET" : "POST", headers, agent: this.agent }, response => {
        if ((response.statusCode ?? 0) >= 300 && (response.statusCode ?? 0) < 400) {
          response.destroy(); finish(new AegirIntegrationError("redirect_rejected")); return;
        }
        const chunks: Buffer[] = []; let size = 0;
        response.on("data", chunk => {
          size += chunk.length;
          if (size > 2 * 1024 * 1024) { response.destroy(); finish(new AegirIntegrationError("invalid_server_response")); }
          else chunks.push(Buffer.from(chunk));
        });
        response.on("error", () => finish(new AegirIntegrationError("authoritative_access_unavailable")));
        response.on("end", () => {
          try {
            if (signal?.aborted) throw new AegirIntegrationError("cancelled");
            if (size && String(response.headers["content-type"]).split(";", 1)[0].trim().toLowerCase() !== "application/json") throw new AegirIntegrationError("invalid_server_response");
            const value = size ? strictJson(new TextDecoder("utf-8", { fatal: true }).decode(Buffer.concat(chunks))) : null;
            finish(undefined, { status: response.statusCode ?? 0, value });
          } catch { finish(new AegirIntegrationError(signal?.aborted ? "cancelled" : "invalid_server_response")); }
        });
      });
      const abort = () => { req.destroy(); finish(new AegirIntegrationError("cancelled")); };
      const timer = setTimeout(() => { req.destroy(); finish(new AegirIntegrationError("deadline_exceeded")); }, this.timeoutMs);
      const finish = (error?: Error, result?: { status: number; value: any }) => {
        if (done) return; done = true; clearTimeout(timer); signal?.removeEventListener("abort", abort);
        this.active.delete(req); if (error) reject(error); else resolve(result!);
      };
      this.active.add(req); signal?.addEventListener("abort", abort, { once: true });
      req.on("error", error => finish(error instanceof AegirIntegrationError ? error : new AegirIntegrationError(this.disposed ? "disposed" : signal?.aborted ? "cancelled" : "authoritative_access_unavailable")));
      if (data !== undefined) req.write(data); req.end();
    });
  }
  close() { this.disposed = true; for (const req of this.active) req.destroy(); this.active.clear(); this.agent.destroy(); }
}
export interface AegirIntegrationOptions {
  apiBaseUrl: string; webBaseUrl: string; organizationId: string; applicationId: string;
  applicationCredential: string; journal: AuthorizationJournal; certificateSha256?: string; timeoutMs?: number;
}
export interface OrganizationApplicationAccessSession {
  accessToken: string; expiresAtUtc: string; organizationId: string; applicationId: string;
  subjectId: string; authorizationEpoch: number;
}
export class AegirIntegrationClient {
  private readonly api: SafeHttpsTransport; private readonly web: SafeHttpsTransport;
  private connected = false; private disposed = false; private tail: Promise<unknown> = Promise.resolve();
  private readonly lifetime = new AbortController();
  constructor(private readonly options: AegirIntegrationOptions) {
    if (!text(options.applicationCredential) || /[^\x21-\x7e]/.test(options.applicationCredential) || !text(options.organizationId, 256) || !text(options.applicationId, 256) ||
        !Number.isFinite(options.timeoutMs ?? 15000) || (options.timeoutMs ?? 15000) <= 0 || (options.timeoutMs ?? 15000) > 120000)
      throw new AegirIntegrationError("invalid_configuration");
    this.api = new SafeHttpsTransport(options.apiBaseUrl, options.certificateSha256, options.timeoutMs ?? 15000);
    this.web = new SafeHttpsTransport(options.webBaseUrl, options.certificateSha256, options.timeoutMs ?? 15000);
    options.journal.setConnected(false);
  }
  private ready() { if (this.disposed) throw new AegirIntegrationError("disposed"); }
  private serial<T>(action: () => Promise<T>): Promise<T> {
    const task = this.tail.then(() => { this.ready(); return action(); });
    this.tail = task.catch(() => {}); return task;
  }
  private disconnected() { this.connected = false; this.options.journal.setConnected(false); }
  async authenticate(username: string, password: string, challengeId?: string, totpCode?: string, signal?: AbortSignal): Promise<OrganizationApplicationAccessSession> {
    this.ready();
    if (!text(username, 320) || typeof password !== "string" || password.length < 1 || password.length > 2048 ||
        (challengeId !== undefined && !text(challengeId)) || (totpCode !== undefined && !text(totpCode, 128)))
      throw new AegirIntegrationError("invalid_authentication_request");
    const { status, value } = await this.web.request("account/organization-access", {
      username, password, organizationId: this.options.organizationId, applicationId: this.options.applicationId, challengeId, totpCode }, undefined, signal);
    this.ready();
    if (status === 400 && value?.error === "mfa_required" && text(value.challengeId)) throw new AegirMfaRequired(value.challengeId);
    if (status !== 200) throw new AegirIntegrationError("authentication_denied");
    const v = object(value);
    if (!["accessToken", "expiresAtUtc", "organizationId", "applicationId", "subjectId", "authorizationEpoch"].every(key => own(v, key)) ||
        !text(v.accessToken) || !text(v.subjectId) || v.organizationId !== this.options.organizationId || v.applicationId !== this.options.applicationId ||
        !text(v.expiresAtUtc) || !Number.isFinite(Date.parse(v.expiresAtUtc)) || Date.parse(v.expiresAtUtc) <= Date.now() || !integer(v.authorizationEpoch))
      throw new AegirIntegrationError("invalid_server_response");
    return v as OrganizationApplicationAccessSession;
  }
  private async request(path: string, body?: object, signal?: AbortSignal) {
    const result = await this.api.request("v1/authorization/" + path, body, this.options.applicationCredential, signal);
    this.ready();
    if (![200, 204].includes(result.status)) throw new AegirIntegrationError([401, 403].includes(result.status) ? "backend_credential_denied" : "invalid_server_response");
    return result.value;
  }
  private async reconcile(signal?: AbortSignal) {
    this.disconnected();
    const s = snapshot(await this.request("snapshot", undefined, signal));
    this.options.journal.applySnapshot(s);
    await this.request("snapshot/ack", { snapshotId: s.snapshotId }, signal);
  }
  private async cycle(signal?: AbortSignal, acknowledge = true): Promise<any> {
    const batch = object(await this.request("events?limit=100", undefined, signal));
    if (typeof batch.requiresSnapshot !== "boolean" || !Array.isArray(batch.events) || batch.events.length > 100 || !integer(batch.retryAfterSeconds))
      throw new AegirIntegrationError("invalid_server_response");
    if (batch.requiresSnapshot) { await this.reconcile(signal); return { reconciled: true, newEffects: 0, empty: false }; }
    if (batch.reason === "retry_backoff") return { backoff: Math.min(30, Math.max(1, batch.retryAfterSeconds)), newEffects: 0, empty: false };
    if (batch.events.length === 0) return { newEffects: 0, empty: true };
    if (!text(batch.deliveryId)) throw new AegirIntegrationError("invalid_server_response");
    const result = this.options.journal.apply(batch.events);
    if (result.requiresSnapshot) { await this.reconcile(signal); return { reconciled: true, newEffects: 0, empty: false }; }
    if (acknowledge) await this.request("ack", { deliveryId: batch.deliveryId }, signal); else this.disconnected();
    return { newEffects: result.newEffects, empty: false, acknowledged: acknowledge };
  }
  private async reconnectCore(signal?: AbortSignal) {
    this.disconnected(); let effects = 0; let reconciled = false;
    try {
      for (let attempt = 0; attempt < 20; attempt++) {
        const result = await this.cycle(signal); effects += result.newEffects;
        this.ready();
        if (result.reconciled) reconciled = true;
        if (result.backoff) await this.delay(result.backoff * 1000, signal);
        else if (result.empty) {
          if (!reconciled) { await this.reconcile(signal); reconciled = true; continue; }
          this.connected = true; this.options.journal.setConnected(true); return { connected: true, newEffects: effects };
        }
      }
      throw new AegirIntegrationError("reconciliation_limit");
    } catch (error) { this.disconnected(); throw error; }
  }
  reconnect(signal?: AbortSignal) { return this.serial(() => this.reconnectCore(signal)); }
  poll(signal?: AbortSignal, acknowledge = true) {
    return this.serial(async () => {
      if (!this.connected) return this.reconnectCore(signal);
      try {
        const result = await this.cycle(signal, acknowledge);
        if (result.reconciled) return this.reconnectCore(signal);
        return { ...result, connected: this.connected };
      } catch (error) { this.disconnected(); throw error; }
    });
  }
  private deny(reason: string): AuthorizationProtectedDecision {
    return { isAuthorized: false, reason, applicationSubjectId: null, authorizationEpoch: 0, effectiveGroupIds: [], permissions: [] };
  }
  private async authorizeCore(accessToken: string, operation: string, signal?: AbortSignal): Promise<AuthorizationProtectedDecision> {
    if (!["read", "write"].includes(operation)) return this.deny("unsupported_operation");
    if (signal?.aborted) throw new AegirIntegrationError("cancelled");
    if (!this.connected) return this.deny("event_reconciliation_required");
    try {
      const { status, value } = await this.api.request("v1/authorization/check", { accessToken, operation }, this.options.applicationCredential, signal);
      this.ready();
      const v = object(value);
      const valid = ["isAuthorized", "reason", "applicationSubjectId", "authorizationEpoch", "effectiveGroupIds", "permissions"].every(key => own(v, key)) &&
        [200, 403].includes(status) && typeof v.isAuthorized === "boolean" && status === (v.isAuthorized ? 200 : 403) && text(v.reason) && integer(v.authorizationEpoch) &&
        (v.applicationSubjectId === null || text(v.applicationSubjectId)) &&
        Array.isArray(v.effectiveGroupIds) && v.effectiveGroupIds.length <= 100 && new Set(v.effectiveGroupIds).size === v.effectiveGroupIds.length && v.effectiveGroupIds.every((g: unknown) => text(g)) &&
        Array.isArray(v.permissions) && v.permissions.length <= 2 && new Set(v.permissions).size === v.permissions.length && v.permissions.every((p: unknown) => p === "read" || p === "write");
      if (!valid || (v.isAuthorized && (status !== 200 || v.reason !== "authorized" || !text(v.applicationSubjectId) || !v.effectiveGroupIds.length || !v.permissions.includes(operation))))
        throw new AegirIntegrationError("invalid_authority_response");
      if (!v.isAuthorized && v.reason === "event_reconciliation_required") this.disconnected();
      return v as AuthorizationProtectedDecision;
    } catch (error) {
      this.disconnected();
      if (error instanceof AegirIntegrationError && ["cancelled", "disposed"].includes(error.code)) throw error;
      return this.deny(error instanceof AegirIntegrationError ? error.code : "authoritative_access_unavailable");
    }
  }
  authorize(accessToken: string, operation: string, signal?: AbortSignal) {
    return this.serial(() => this.authorizeCore(accessToken, operation, signal));
  }
  /** Revalidate after host preparation, immediately before commit. No cross-database atomicity is claimed. */
  execute(accessToken: string, operation: string, commit: () => Promise<void> | void,
          prepare?: () => Promise<void> | void, signal?: AbortSignal) {
    return this.serial(async () => {
      let decision = await this.authorizeCore(accessToken, operation, signal);
      if (!decision.isAuthorized) return decision;
      if (prepare) await prepare();
      this.ready();
      decision = await this.authorizeCore(accessToken, operation, signal);
      if (decision.isAuthorized) { this.ready(); if (signal?.aborted) throw new AegirIntegrationError("cancelled"); await commit(); }
      return decision;
    });
  }
  disconnect() { return this.serial(async () => { this.disconnected(); }); }
  close() { if (!this.disposed) { this.disposed = true; this.lifetime.abort(); this.api.close(); this.web.close(); this.disconnected(); } }
  private delay(ms: number, signal?: AbortSignal) {
    if (signal?.aborted || this.lifetime.signal.aborted) return Promise.reject(new AegirIntegrationError(this.disposed ? "disposed" : "cancelled"));
    return new Promise<void>((resolve, reject) => {
      const cleanup = () => { signal?.removeEventListener("abort", abort); this.lifetime.signal.removeEventListener("abort", abort); };
      const abort = () => { clearTimeout(timer); cleanup(); reject(new AegirIntegrationError(this.disposed ? "disposed" : "cancelled")); };
      const timer = setTimeout(() => { cleanup(); resolve(); }, ms);
      signal?.addEventListener("abort", abort, { once: true });
      this.lifetime.signal.addEventListener("abort", abort, { once: true });
    });
  }
}

