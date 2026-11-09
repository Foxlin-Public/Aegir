// Copyright Foxlin Industries. Internal bounded transport for the retained public SDK.
import { request as requestHttps } from "node:https";
import { TLSSocket, checkServerIdentity } from "node:tls";
import { createHash } from "node:crypto";

export interface LegacySecurityOptions {
  timeoutMs?: number;
  signal?: AbortSignal;
  /** Host-owned code: this adapter can observe credentials and must honor the wire contract. */
  allowTrustedCustomTransport?: boolean;
  /** Explicit non-production leaf pin, permitted only for an HTTPS loopback origin. */
  certificateSha256?: string;
  expectedTenantId?: string;
  expectedApplicationId?: string;
  expectedSubjectId?: string;
}
export class LegacyFailure extends Error {
  constructor(public readonly code: string) { super(code); }
}
const MAX_BYTES = 1024 * 1024;
const fail = (): never => { throw new LegacyFailure("invalid_server_response"); };
const object = (v: unknown): Record<string, any> => {
  if (!v || typeof v !== "object" || Array.isArray(v)) return fail();
  return v as Record<string, any>;
};
const text = (v: any, limit = 512): v is string => typeof v === "string" && v.trim().length > 0 && v.length <= limit && !/[\r\n\0]/.test(v);
const integer = (v: any, min = 0): boolean => Number.isSafeInteger(v) && v >= min;
const nullable = (v: any): boolean => v === null || typeof v === "string";
function strings(v: any): v is string[] {
  return Array.isArray(v) && v.length <= 4096 && v.every(x => text(x)) && new Set(v).size === v.length;
}
function requireFields(v: any, names: string[]): Record<string, any> {
  const o = object(v); if (!names.every(k => Object.hasOwn(o, k))) fail(); return o;
}
function equal(actual: any, expected: any): void {
  if (expected !== undefined && expected !== null && actual !== expected) fail();
}
function future(v: any): boolean { return text(v) && Number.isFinite(Date.parse(v)) && Date.parse(v) > Date.now(); }

export function cleanLegacyBase(value: string): string {
  try {
    if (typeof value !== "string" || value.length > 2048 || value !== value.trim() || /[\s\\]/.test(value) ||
        /(?:^|\/)(?:\.|%2e){1,2}(?:\/|$)/i.test(value) || /%2f|%5c/i.test(value)) throw 0;
    const u = new URL(value);
    if (u.protocol !== "https:" || !u.hostname || u.username || u.password || u.search || u.hash) throw 0;
    return u.toString().replace(/\/+$/, "");
  } catch { throw new LegacyFailure("invalid_configuration"); }
}

/** Reject duplicate keys on the bounded original UTF-8 text, before normal JSON decoding. */
export function parseLegacyJson(source: string): any {
  if (Buffer.byteLength(source) > MAX_BYTES) fail();
  let i = 0, nodes = 0;
  const space = () => { while (i < source.length && /[\t\n\r ]/.test(source[i])) i++; };
  const string = (): string => {
    const start = i++;
    while (i < source.length) {
      if (source[i] === "\\") { i += 2; continue; }
      if (source[i++] === '"') {
        const v = JSON.parse(source.slice(start, i)); if (v.length > 262144) fail(); return v;
      }
    }
    return fail();
  };
  const value = (depth = 0): void => {
    if (depth > 32 || ++nodes > 16384) fail();
    space();
    if (source[i] === "{") {
      i++; space(); const keys = new Set<string>();
      if (source[i] === "}") { i++; return; }
      while (i < source.length) {
        space(); if (source[i] !== '"') fail();
        const key = string(); if (keys.has(key) || keys.size >= 4096) fail(); keys.add(key);
        space(); if (source[i++] !== ":") fail(); value(depth + 1); space();
        const end = source[i++]; if (end === "}") return; if (end !== ",") fail();
      }
    } else if (source[i] === "[") {
      i++; space(); if (source[i] === "]") { i++; return; }
      let count = 0;
      while (i < source.length) {
        if (++count > 4096) fail(); value(depth + 1); space();
        const end = source[i++]; if (end === "]") return; if (end !== ",") fail();
      }
    } else if (source[i] === '"') { string(); return; }
    else {
      const start = i; while (i < source.length && !/[\s,\]}]/.test(source[i])) i++;
      if (start === i) fail(); const v = JSON.parse(source.slice(start, i));
      if (typeof v === "number" && !Number.isFinite(v)) fail(); return;
    }
    fail();
  };
  try { value(); space(); if (i !== source.length) fail(); return JSON.parse(source); }
  catch { return fail(); }
}

export class LegacyTransport {
  readonly baseUrl: string;
  #closed = false;
  #pending = new Set<AbortController>();
  #timeout: number;
  #options: LegacySecurityOptions;
  #fetcher?: typeof fetch;
  constructor(baseUrl: string, options: LegacySecurityOptions, fetcher?: typeof fetch) {
    this.baseUrl = cleanLegacyBase(baseUrl);
    this.#options = { signal: options.signal, certificateSha256: options.certificateSha256 };
    this.#fetcher = fetcher;
    this.#timeout = options.timeoutMs ?? 10000;
    if (!integer(this.#timeout, 1) || this.#timeout > 30000 || (fetcher && options.allowTrustedCustomTransport !== true))
      throw new LegacyFailure("invalid_configuration");
    if (options.certificateSha256 && (!/^[a-fA-F0-9]{64}$/.test(options.certificateSha256) ||
        !["localhost", "127.0.0.1", "[::1]"].includes(new URL(this.baseUrl).hostname)))
      throw new LegacyFailure("invalid_configuration");
    for (const v of [options.expectedTenantId, options.expectedApplicationId, options.expectedSubjectId])
      if (v !== undefined && !text(v)) throw new LegacyFailure("invalid_configuration");
  }
  toJSON(): object { return { type: "AegirLegacyTransport", closed: this.#closed }; }
  cancelPending(): void { for (const c of this.#pending) c.abort(); }
  close(): void { this.#closed = true; this.cancelPending(); }
  async run<T>(action: (signal: AbortSignal) => Promise<T>): Promise<T> {
    if (this.#closed) throw new LegacyFailure("client_closed");
    if (this.#pending.size >= 16) throw new LegacyFailure("transport_error");
    const controller = new AbortController(), external = this.#options.signal;
    const abort = () => controller.abort(); external?.addEventListener("abort", abort, { once: true });
    if (external?.aborted) controller.abort();
    this.#pending.add(controller);
    const timer = setTimeout(abort, this.#timeout);
    try {
      if (controller.signal.aborted) throw new LegacyFailure("request_cancelled");
      const result = await this.wait(action(controller.signal), controller.signal);
      if (this.#closed || controller.signal.aborted) throw new LegacyFailure("request_cancelled");
      return result;
    } finally { clearTimeout(timer); external?.removeEventListener("abort", abort); this.#pending.delete(controller); }
  }
  async wait<T>(action: Promise<T>, signal: AbortSignal): Promise<T> {
    let abort: (() => void) | undefined;
    try {
      return await Promise.race([action, new Promise<never>((_, reject) => {
        abort = () => reject(new LegacyFailure("request_cancelled"));
        signal.addEventListener("abort", abort, { once: true }); if (signal.aborted) abort();
      })]);
    } finally { if (abort) signal.removeEventListener("abort", abort); }
  }
  async observe(action: () => void | Promise<void> | undefined, signal: AbortSignal): Promise<void> {
    if (signal.aborted || this.#closed) throw new LegacyFailure("request_cancelled");
    try { await this.wait(Promise.resolve(action()), signal); } catch { /* Host observability is best effort. */ }
    if (signal.aborted || this.#closed) throw new LegacyFailure("request_cancelled");
  }
  async request(path: string, init: RequestInit, signal: AbortSignal): Promise<{ status: number; value: any; correlationId: string | null }> {
    if (signal.aborted || this.#closed) throw new LegacyFailure("request_cancelled");
    const url = this.baseUrl + "/v1" + path;
    const result = await this.wait(this.#fetcher ? this.custom(url, init, signal) : this.native(url, init, signal), signal);
    if (signal.aborted || this.#closed) throw new LegacyFailure("request_cancelled");
    return result;
  }
  private decode(status: number, headers: Headers, bytes: Buffer): { status: number; value: any; correlationId: string | null } {
    const media = (headers.get("content-type") ?? "").split(";", 1)[0].trim().toLowerCase();
    if (bytes.length > MAX_BYTES || (bytes.length && media !== "application/json" && !(status >= 400 && media === "application/problem+json"))) fail();
    const value = bytes.length ? parseLegacyJson(new TextDecoder("utf-8", { fatal: true }).decode(bytes)) : null;
    if (status >= 200 && status < 300 && value === null) fail();
    return { status, value, correlationId: headers.get("x-correlation-id") };
  }
  private async custom(url: string, init: RequestInit, signal: AbortSignal) {
    const response = await this.#fetcher!(url, { ...init, redirect: "error", credentials: "omit", cache: "no-store", signal });
    if (response.redirected || (response.url && response.url !== url) || signal.aborted) fail();
    const chunks: Buffer[] = []; let size = 0;
    if (response.body) {
      const reader = response.body.getReader();
      const cancel = () => { void reader.cancel().catch(() => {}); };
      signal.addEventListener("abort", cancel, { once: true });
      try {
        while (true) {
          const next = await reader.read(); if (next.done) break;
          size += next.value.byteLength; if (size > MAX_BYTES || signal.aborted) fail(); chunks.push(Buffer.from(next.value));
        }
      } finally { signal.removeEventListener("abort", cancel); await reader.cancel().catch(() => {}); reader.releaseLock(); }
    }
    return this.decode(response.status, response.headers, Buffer.concat(chunks));
  }
  private native(url: string, init: RequestInit, signal: AbortSignal): Promise<{ status: number; value: any; correlationId: string | null }> {
    return new Promise((resolve, reject) => {
      const headers = Object.fromEntries(new Headers(init.headers));
      const body = init.body == null ? undefined : Buffer.from(String(init.body), "utf8");
      if (body && body.length > MAX_BYTES) return reject(new LegacyFailure("invalid_request"));
      if (body) headers["content-length"] = String(body.length);
      // Native HTTPS does not consult HTTP(S)_PROXY and never follows redirects.
      const request = requestHttps(url, { method: init.method ?? "GET", headers, agent: false,
        rejectUnauthorized: !this.#options.certificateSha256, signal }, response => {
        const chunks: Buffer[] = []; let size = 0;
        const h = new Headers();
        for (const [k, v] of Object.entries(response.headers)) if (v !== undefined) h.set(k, Array.isArray(v) ? v.join(",") : v);
        response.on("data", chunk => {
          size += chunk.length;
          if (size > MAX_BYTES) { request.destroy(); reject(new LegacyFailure("invalid_server_response")); }
          else chunks.push(Buffer.from(chunk));
        });
        response.on("error", () => reject(new LegacyFailure("transport_error")));
        response.on("end", () => {
          try { resolve(this.decode(response.statusCode ?? 0, h, Buffer.concat(chunks))); }
          catch { reject(new LegacyFailure("invalid_server_response")); }
        });
      });
      request.on("error", () => reject(new LegacyFailure(signal.aborted ? "request_cancelled" : "transport_error")));
      request.on("socket", socket => {
        (socket as TLSSocket).once("secureConnect", () => {
          if (signal.aborted) { request.destroy(); return; }
          const pin = this.#options.certificateSha256;
          const certificate = (socket as TLSSocket).getPeerCertificate();
          const raw = certificate.raw, host = new URL(url).hostname.replace(/^\[|\]$/g, "");
          const now = Date.now(), from = Date.parse(certificate.valid_from), until = Date.parse(certificate.valid_to);
          if (pin && (!raw || createHash("sha256").update(raw).digest("hex") !== pin.toLowerCase() ||
              checkServerIdentity(host, certificate) !== undefined || !Number.isFinite(from) || !Number.isFinite(until) ||
              from > now || until <= now)) {
            reject(new LegacyFailure("transport_error")); request.destroy(); return;
          }
          // Credential bytes are queued only after TLS and any explicit leaf pin pass.
          request.end(body);
        });
      });
    });
  }
}

export function safeLegacyValue(value: any, secrets: string[]): any {
  if (typeof value === "string") {
    let result = value.slice(0, 2048);
    for (const secret of secrets) if (secret) result = result.split(secret).join("[redacted]");
    return result.replace(/[\r\n\0]/g, " ");
  }
  if (Array.isArray(value)) return value.slice(0, 32).map(v => safeLegacyValue(v, secrets));
  if (value && typeof value === "object") return Object.fromEntries(Object.entries(value).slice(0, 32).map(([k, v]) => {
    const safeKey = safeLegacyValue(k, secrets);
    return [safeKey, safeKey !== k || /token|password|secret|credential|authorization|key|payload/i.test(k) ? "[redacted]" : safeLegacyValue(v, secrets)];
  }));
  return value;
}

export function validateLegacyResponse(operation: string, path: string, value: any, input: any,
    options: LegacySecurityOptions, agentSubject?: string): void {
  const o = Array.isArray(value) ? null : object(value);
  const segments = path.split("?", 1)[0].split("/").filter(Boolean).map(decodeURIComponent);
  const tenant = (v: any) => equal(v, options.expectedTenantId);
  const subject = (v: any) => equal(v, options.expectedSubjectId);
  const graphBinding = (v: any, requested: string) => {
    const id = object(v).graphId;
    if (!["graph:" + requested, "graph:developer:" + requested, "graph:user:" + requested].includes(id)) fail();
  };
  const transaction = (v: any) => {
    requireFields(v, ["transactionId", "tenantId", "callerPrincipalType", "callerPrincipalId", "declaredAction", "authorizationDecision", "status"]);
    if (![v.transactionId, v.tenantId, v.callerPrincipalId, v.declaredAction].every(x => text(x)) ||
        !["Human", "DeveloperApplication", "Agent"].includes(v.callerPrincipalType) ||
        !["Pending", "Allow", "Deny"].includes(v.authorizationDecision) ||
        !["Created", "Authorized", "Rejected", "InProgress", "Completed", "Failed", "Expired"].includes(v.status)) fail();
    if ((v.authorizationDecision === "Deny" && ["Authorized", "InProgress", "Completed"].includes(v.status)) ||
        (v.authorizationDecision === "Pending" && ["Authorized", "InProgress", "Completed"].includes(v.status))) fail();
    tenant(v.tenantId);
  };
  const agent = (v: any) => {
    requireFields(v, ["agentId", "tenantId", "developerAccountId", "applicationId", "displayName", "status", "scopes", "createdAtUtc", "expiresAtUtc", "revokedAtUtc"]);
    if (![v.agentId, v.tenantId, v.developerAccountId, v.displayName, v.status, v.createdAtUtc].every(x => text(x)) ||
        !strings(v.scopes) || !nullable(v.applicationId) || !nullable(v.expiresAtUtc) || !nullable(v.revokedAtUtc)) fail();
    tenant(v.tenantId); equal(v.applicationId, options.expectedApplicationId);
  };
  if (["getToken", "useAgentKey"].includes(operation)) {
    const t = requireFields(o, ["access_token", "token_type", "expires_in", "expires_at", "scope", "scopes", "tenant_id", "subject"]);
    if (!text(t.access_token, 16384) || t.token_type !== "Bearer" || !integer(t.expires_in, 1) || !future(t.expires_at) ||
        typeof t.scope !== "string" || !strings(t.scopes) || t.scope !== t.scopes.join(" ") || !text(t.tenant_id) || !text(t.subject)) fail();
    const requested = typeof input.scope === "string" ? input.scope.trim().split(/\s+/).filter(Boolean) : [];
    if (requested.length && t.scopes.some((s: string) => !requested.includes(s))) fail();
    tenant(t.tenant_id); subject(t.subject); equal(t.subject, agentSubject);
  } else if (operation === "introspectToken") {
    if (typeof o!.active !== "boolean") fail();
    if (o!.active) {
      requireFields(o, ["sub", "tenant_id", "exp", "scopes", "roles"]);
      if (!text(o!.sub) || !text(o!.tenant_id) || !integer(o!.exp, 1) || o!.exp * 1000 <= Date.now() || !strings(o!.scopes) || !strings(o!.roles)) fail();
      tenant(o!.tenant_id); subject(o!.sub); equal(o!.app, options.expectedApplicationId);
    } else if (["sub", "tenant_id", "exp", "scopes", "roles"].some(k => Object.hasOwn(o!, k))) fail();
  } else if (operation === "verifyTransactionReceipt") {
    requireFields(o, ["valid", "status", "detail"]);
    if (typeof o!.valid !== "boolean" || !nullable(o!.detail) ||
        !["Valid", "SignatureInvalid", "UnknownSigningKey", "SignedOutsideKeyLifetime", "Malformed"].includes(o!.status) ||
        o!.valid !== (o!.status === "Valid")) fail();
  } else if (operation === "revokeToken") { if (o!.status !== "revoked") fail(); }
  else if (["createTransaction", "getTransaction", "getTransactionReceipt"].includes(operation)) {
    transaction(o);
    if (operation !== "createTransaction") equal(o!.transactionId, segments[1]);
    else { equal(o!.declaredAction, input.declaredAction); if (input.subjectPrincipalId) equal(o!.subjectPrincipalId, input.subjectPrincipalId); }
    if (operation === "getTransactionReceipt") {
      requireFields(o, ["eventChainRoot", "issuedAtUtc", "signingKid", "algorithm", "signature"]);
      if (![o!.eventChainRoot, o!.issuedAtUtc, o!.signingKid, o!.algorithm, o!.signature].every(x => text(x, 32768))) fail();
    }
  } else if (operation === "getTransactionEvents") {
    if (!Array.isArray(value)) fail();
    for (const e of value) if (!integer(e.sequence, 1) || !text(e.eventType) || !text(e.status) || !text(e.eventHash)) fail();
  } else if (operation === "registerAgent") {
    requireFields(o, ["agent", "credentialId", "agentKey"]); agent(o!.agent);
    if (!text(o!.credentialId) || !text(o!.agentKey, 16384) || !o!.agentKey.startsWith(o!.agent.agentId + ":")) fail();
    if (input.applicationId) equal(o!.agent.applicationId, input.applicationId);
    if (input.scopes && o!.agent.scopes.some((s: string) => !input.scopes.includes(s))) fail();
  } else if (operation === "listAgents") { if (!Array.isArray(value)) fail(); for (const v of value) agent(v); }
  else if (operation === "revokeAgent") { agent(o); equal(o!.agentId, segments[1]); if (o!.status !== "Revoked") fail(); }
  else if (operation === "bindProvider") {
    if (!text(o!.bindingId) || !strings(o!.allowedModelIds) || Object.hasOwn(o!, "apiKey")) fail();
    equal(o!.agentPrincipalId, segments[1]); equal(o!.providerId, input.providerId);
    if (input.allowedModelIds && o!.allowedModelIds.some((m: string) => !input.allowedModelIds.includes(m))) fail();
  } else if (operation === "invokeProvider") {
    for (const k of ["transactionId", "providerId", "modelId"]) equal(o![k], input[k]);
    if (!text(o!.invocationId) || !text(o!.agentPrincipalId) || typeof o!.succeeded !== "boolean" ||
        typeof o!.errorRetryable !== "boolean" || !nullable(o!.content) || !nullable(o!.errorKind) ||
        (o!.succeeded && o!.errorKind !== null) || (!o!.succeeded && !text(o!.errorKind))) fail();
  } else if (operation === "sendAgentMessage") {
    equal(o!.transactionId, input.transactionId); const h = object(object(o!.envelope).header);
    equal(h.transactionId, input.transactionId); equal(h.recipientPrincipalId, input.recipientAgentId); equal(h.action, input.action);
    if (!text(o!.envelope.envelopeId) || !["kemCiphertext", "aeadNonce", "ciphertext", "tag", "signature"].every(k => text(o!.envelope[k], 262144))) fail();
  } else if (operation === "receiveAgentMessage") {
    equal(o!.transactionId, input.transactionId); if (!text(o!.senderAgentId) || !text(o!.action) || typeof o!.payload !== "string") fail();
    if (input.envelope?.header) { equal(o!.action, input.envelope.header.action); equal(o!.senderAgentId, input.envelope.header.senderPrincipalId); }
  } else if (operation === "scanIdentity") {
    equal(o!.subjectId, segments[2]); graphBinding(o!.graph, segments[2]); graphBinding(o!.exposure, segments[2]);
    equal(o!.exposure.graphId, o!.graph.graphId);
  }
  else if (operation === "getExposureSummary") graphBinding(o!, segments[2]);
  else if (operation === "getIdentityGraph") {
    graphBinding(o!, segments[2]);
    if (!text(o!.graphId) || !Array.isArray(o!.nodes) || !Array.isArray(o!.edges)) fail(); object(o!.scores);
  } else if (operation === "performAction") equal(o!.subjectId, input.subjectId);
  else if (operation === "reverseAction") equal(o!.actionId, segments[2]);
  else if (operation === "getActionHistory") { if (!Array.isArray(value)) fail(); for (const v of value) equal(v.subjectId, segments[3]); }
  else if (operation === "listProviders") { if (!Array.isArray(value) || !value.every(v => text(v.providerId))) fail(); }
}

// Exact 1-based public C# enum values, normalized only within the identity DTO family.
const legacyEnums: Record<string,string[]> = {
 nodeType:["Platform","Developer","DeveloperKey","Application","Environment","User","Device","Credential","Challenge","Token","AuditAnchor","PolicyScope","ExternalService"],
 edgeType:["Owns","Issued","Registered","BelongsTo","AuthorizedFor","ScopedTo","Uses","PresentedBy","DerivedFrom","ApprovedBy","RevokedBy","AnchoredBy","ConnectedTo","ObservedOn"],
 category:["WeakConnection","UnknownConnection","StaleCredential","HighRiskLinkage"],severity:["Low","Medium","High"],
 actionType:["LockIdentity","DisconnectService","VerifyConnection","RequestClarity"],actionStatus:["Completed","Reversed"]
};
function enumName(kind:string,value:any):string {
 const names=legacyEnums[kind];
 if (typeof value === "number" && Number.isInteger(value) && value>=1 && value<=names.length) return names[value-1];
 if (typeof value === "string" && names.includes(value)) return value;
 return fail();
}
export function legacyRequestBody(operation:string,input:any):any {
 if (operation!=="performAction") return input;
 const name=enumName("actionType",input.actionType);
 return {...input,actionType:legacyEnums.actionType.indexOf(name)+1};
}
export function normalizeLegacyIdentityResponse(operation:string,value:any):any {
 const action=(a:any)=>{a=object(a);a.actionType=enumName("actionType",a.actionType);a.status=enumName("actionStatus",a.status);};
 const graph=(g:any)=>{g=object(g);const scores=object(g.scores);if(!["exposureScore","trustScore","connectionClarityScore"].every(k=>typeof scores[k]==="number"&&Number.isFinite(scores[k])))fail();for(const n of g.nodes??[])n.nodeType=enumName("nodeType",n.nodeType);for(const e of g.edges??[])e.edgeType=enumName("edgeType",e.edgeType);};
 const exposure=(e:any)=>{e=object(e);for(const f of e.findings??[]){f.category=enumName("category",f.category);f.severity=enumName("severity",f.severity);}};
 if(operation==="scanIdentity"){graph(value.graph);exposure(value.exposure);for(const a of value.actionHistory??[])action(a);}
 else if(operation==="getIdentityGraph")graph(value);
 else if(operation==="getExposureSummary")exposure(value);
 else if(operation==="getActionHistory")for(const a of value)action(a);
 else if(["performAction","reverseAction"].includes(operation))action(value);
 return value;
}
