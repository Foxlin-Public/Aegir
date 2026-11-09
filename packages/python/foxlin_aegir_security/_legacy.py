"""Foxlin Industries. Internal bounded wire and response checks for the retained SDK."""
from __future__ import annotations
import hashlib
import http.client
import json
import math
import queue
import re
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from urllib.parse import urlsplit, unquote

MAX_BYTES = 1024 * 1024
_WORKERS = threading.BoundedSemaphore(16)


class LegacyFailure(Exception):
    pass


def _fail():
    raise LegacyFailure("invalid_server_response")


def text(v, limit=512):
    return isinstance(v, str) and 0 < len(v.strip()) <= limit and not re.search(r"[\r\n\0]", v)


def integer(v, minimum=0):
    return type(v) is int and minimum <= v <= 9007199254740991


def strings(v):
    return isinstance(v, list) and len(v) <= 4096 and all(text(x) for x in v) and len(set(v)) == len(v)


def obj(v):
    if not isinstance(v, dict):
        _fail()
    return v


def fields(v, names):
    if not set(names).issubset(obj(v)):
        _fail()
    return v


def equal(actual, expected):
    if expected is not None and actual != expected:
        _fail()


def bounded(value):
    nodes = 0
    def visit(v, depth):
        nonlocal nodes
        nodes += 1
        if depth > 32 or nodes > 16384:
            _fail()
        if isinstance(v, (dict, list)):
            if len(v) > 4096:
                _fail()
            if isinstance(v, dict):
                if not all(isinstance(k, str) and len(k) <= 262144 for k in v):
                    _fail()
                values = v.values()
            else:
                values = v
            for item in values:
                visit(item, depth + 1)
        elif isinstance(v, str):
            if len(v) > 262144:
                _fail()
        elif isinstance(v, float):
            if not math.isfinite(v):
                _fail()
        elif v is not None and type(v) not in (bool, int):
            _fail()
    visit(value, 0)
    return value


def strict_json(source):
    if len(source.encode("utf-8")) > MAX_BYTES:
        _fail()
    depth, quoted, escaped = 0, False, False
    for char in source:
        if quoted:
            if escaped: escaped = False
            elif char == "\\": escaped = True
            elif char == '"': quoted = False
        elif char == '"': quoted = True
        elif char in "{[":
            depth += 1
            if depth > 33: _fail()
        elif char in "}]": depth -= 1
    def unique(pairs):
        result = {}
        for k, v in pairs:
            if k in result: _fail()
            result[k] = v
        return result
    try:
        return bounded(json.loads(source, object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError())))
    except (ValueError, UnicodeError, RecursionError, OverflowError):
        raise LegacyFailure("invalid_server_response") from None


def clean_base(value):
    try:
        if not isinstance(value, str) or len(value) > 2048 or re.search(r"[\s\\]", value) or re.search(r"(?:^|/)(?:\.|%2e){1,2}(?:/|$)|%2f|%5c", value, re.I):
            raise ValueError()
        u = urlsplit(value)
        if u.scheme != "https" or not u.hostname or u.username or u.password or u.query or u.fragment:
            raise ValueError()
        _ = u.port
        return value.rstrip("/")
    except (ValueError, TypeError):
        raise LegacyFailure("invalid_configuration") from None


def _wait_worker(action, deadline, cancelled):
    # A slow OS resolver or trusted legacy callback cannot monopolize the caller.
    # Unfinished daemon workers remain capped; they never send SDK credentials themselves.
    if cancelled() or time.monotonic() >= deadline:
        raise LegacyFailure("request_cancelled")
    while not _WORKERS.acquire(timeout=.025):
        if cancelled() or time.monotonic() >= deadline:
            raise LegacyFailure("request_cancelled")
    result = queue.Queue(maxsize=1)
    def work():
        try: result.put((True, action()))
        except Exception: result.put((False, None))
        finally: _WORKERS.release()
    threading.Thread(target=work, daemon=True).start()
    while True:
        if cancelled() or time.monotonic() >= deadline:
            raise LegacyFailure("request_cancelled")
        try:
            ok, value = result.get(timeout=min(.025, max(.001, deadline-time.monotonic())))
            if not ok: raise LegacyFailure("transport_error")
            return value
        except queue.Empty:
            pass


class OwnedTransport:
    def __init__(self, base_url, timeout, pin=None, cancel_event=None):
        self.base_url = clean_base(base_url)
        if isinstance(timeout, bool) or not isinstance(timeout, (float, int)) or not .001 <= timeout <= 30:
            raise LegacyFailure("invalid_configuration")
        self.timeout, self.pin, self.external = timeout, pin, cancel_event
        if pin and (not re.fullmatch(r"[a-fA-F0-9]{64}", pin) or urlsplit(base_url).hostname not in ("localhost", "127.0.0.1", "::1")):
            raise LegacyFailure("invalid_configuration")
        self._lock = threading.Lock()
        self._active = {}
        self._closed = False

    def begin(self):
        with self._lock:
            if self._closed or len(self._active) >= 16:
                raise LegacyFailure("client_closed")
            event = threading.Event(); self._active[event] = None
        return event

    def finish(self, event):
        with self._lock:
            connection = self._active.pop(event, None)
        if connection:
            connection.close()

    def cancelled(self, event):
        return event.is_set() or self._closed or (self.external is not None and self.external.is_set())

    def cancel_pending(self):
        with self._lock:
            for event, connection in self._active.items():
                event.set()
                sock = (connection.sock or getattr(connection, "_aegir_response_socket", None)) if connection is not None else None
                if sock is not None:
                    try: sock.shutdown(socket.SHUT_RDWR)
                    except OSError: pass
                if connection is not None: connection.close()

    def close(self):
        self._closed = True
        self.cancel_pending()

    def run(self, action):
        event = self.begin(); deadline = time.monotonic() + self.timeout
        try:
            value = action((event, deadline))
            if self.cancelled(event) or time.monotonic() >= deadline:
                raise LegacyFailure("request_cancelled")
            return value
        finally:
            self.finish(event)

    def observe(self, callback, value, lifetime):
        event, deadline = lifetime
        if callback is None:
            if self.cancelled(event) or time.monotonic() >= deadline:
                raise LegacyFailure("request_cancelled")
            return
        def invoke():
            try: callback(value)
            except Exception: pass # Host observability is best effort; no raw diagnostics escape.
        _wait_worker(invoke, deadline, lambda: self.cancelled(event))

    def call(self, url, method, headers, body, custom=None, lifetime=None):
        event, deadline = lifetime if lifetime is not None else (self.begin(), time.monotonic() + self.timeout)
        cancelled = lambda: self.cancelled(event)
        def remaining():
            if cancelled() or time.monotonic() >= deadline: raise LegacyFailure("request_cancelled")
            return max(.001, deadline-time.monotonic())
        try:
            remaining()
            if custom is not None:
                status, value = _wait_worker(lambda: custom(url, method, dict(headers), body), deadline, cancelled)
                remaining(); bounded(value)
                if len(json.dumps(value, allow_nan=False).encode()) > MAX_BYTES: _fail()
                return status, value
            u = urlsplit(url)
            # Native HTTPS ignores proxy environment and performs no redirects.
            addresses = _wait_worker(lambda: socket.getaddrinfo(u.hostname, u.port or 443, type=socket.SOCK_STREAM), deadline, cancelled)
            remaining()
            def connect_resolved(addr, timeout=None, source_address=None):
                for index, address in enumerate(addresses):
                    attempt_timeout = max(.001, remaining() / (len(addresses) - index))
                    try: return socket.create_connection((address[4][0], u.port or 443), attempt_timeout, source_address)
                    except OSError: pass
                raise LegacyFailure("transport_error")
            def connect(context):
                candidate = http.client.HTTPSConnection(u.hostname, u.port or 443, timeout=remaining(), context=context)
                candidate._create_connection = connect_resolved
                with self._lock:
                    self._active[event] = candidate
                remaining(); candidate.connect(); remaining()
                return candidate
            if self.pin:
                # Discovery sends no HTTP bytes. Exact leaf trust is confined to a
                # second connection, where OpenSSL enforces hostname and validity.
                discovery_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                discovery_context.check_hostname = False
                discovery_context.verify_mode = ssl.CERT_NONE
                discovery = connect(discovery_context)
                raw = discovery.sock.getpeercert(binary_form=True)
                discovery.close()
                if not raw or hashlib.sha256(raw).hexdigest() != self.pin.lower():
                    raise LegacyFailure("transport_error")
                context = ssl.create_default_context(cadata=ssl.DER_cert_to_PEM_cert(raw))
                context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
                connection = connect(context)
                if hashlib.sha256(connection.sock.getpeercert(binary_form=True)).hexdigest() != self.pin.lower():
                    raise LegacyFailure("transport_error")
            else:
                connection = connect(ssl.create_default_context())
            # No credential-bearing bytes precede handshake and exact development pin checks.
            connection.sock.settimeout(remaining())
            data = body.encode("utf-8") if body is not None else None
            if data is not None and len(data) > MAX_BYTES: _fail()
            connection.request(method, (u.path or "/") + ("?" + u.query if u.query else ""), data, headers)
            response = connection.getresponse()
            with response:
                response_socket = connection.sock or getattr(getattr(response.fp, "raw", None), "_sock", None)
                connection._aegir_response_socket = response_socket
                length = response.getheader("Content-Length")
                if length is not None and (not length.isdigit() or int(length) > MAX_BYTES): _fail()
                chunks, size = [], 0
                while True:
                    sock = response_socket
                    if sock is not None: sock.settimeout(remaining())
                    else: remaining()
                    chunk = response.read(min(65536, MAX_BYTES + 1 - size))
                    if not chunk: break
                    size += len(chunk)
                    if size > MAX_BYTES: _fail()
                    chunks.append(chunk)
                    # A length-delimited response may close its underlying socket when
                    # the last byte is consumed. Do not touch that closed socket again.
                    if response.length == 0 or response.isclosed(): break
                media = (response.getheader("Content-Type") or "").split(";", 1)[0].strip().lower()
                if size and media != "application/json" and not (response.status >= 400 and media == "application/problem+json"):
                    _fail()
                value = strict_json(b"".join(chunks).decode("utf-8", errors="strict")) if size else None
                if 200 <= response.status < 300 and value is None: _fail()
                remaining()
                return response.status, value
        except LegacyFailure:
            raise
        except Exception:
            raise LegacyFailure("transport_error") from None
        finally:
            if lifetime is None:
                self.finish(event)


def safe_value(value, secrets):
    if isinstance(value, str):
        result = value[:2048]
        for secret in secrets:
            if secret: result = result.replace(secret, "[redacted]")
        return re.sub(r"[\r\n\0]", " ", result)
    if isinstance(value, list): return [safe_value(v, secrets) for v in value[:32]]
    if isinstance(value, dict):
        result = {}
        for k,v in list(value.items())[:32]:
            safe_key = safe_value(k,secrets)
            result[safe_key] = "[redacted]" if safe_key != k or re.search(r"token|password|secret|credential|authorization|key|payload", k, re.I) else safe_value(v,secrets)
        return result
    return value


def validate_response(operation, path, value, request, options, agent_subject=None):
    def graph_binding(value, requested):
        if obj(value).get("graphId") not in ("graph:" + requested, "graph:developer:" + requested, "graph:user:" + requested):
            _fail()
    o = None if isinstance(value, list) else obj(value)
    segments = [unquote(p) for p in path.split("?", 1)[0].split("/") if p]
    tenant = lambda v: equal(v, options.get("expected_tenant_id"))
    def transaction(v):
        fields(v, ["transactionId", "tenantId", "callerPrincipalType", "callerPrincipalId", "declaredAction", "authorizationDecision", "status"])
        if not all(text(v[k]) for k in ["transactionId", "tenantId", "callerPrincipalId", "declaredAction"]) or v["callerPrincipalType"] not in ("Human", "DeveloperApplication", "Agent") or v["authorizationDecision"] not in ("Pending", "Allow", "Deny") or v["status"] not in ("Created", "Authorized", "Rejected", "InProgress", "Completed", "Failed", "Expired"): _fail()
        if v["authorizationDecision"] in ("Pending", "Deny") and v["status"] in ("Authorized", "InProgress", "Completed"): _fail()
        tenant(v["tenantId"])
    def agent(v):
        fields(v, ["agentId", "tenantId", "developerAccountId", "applicationId", "displayName", "status", "scopes", "createdAtUtc", "expiresAtUtc", "revokedAtUtc"])
        if not all(text(v[k]) for k in ["agentId", "tenantId", "developerAccountId", "displayName", "status", "createdAtUtc"]) or not strings(v["scopes"]): _fail()
        tenant(v["tenantId"]); equal(v["applicationId"], options.get("expected_application_id"))
    if operation in ("getToken", "useAgentKey"):
        t = fields(o, ["access_token", "token_type", "expires_in", "expires_at", "scope", "scopes", "tenant_id", "subject"])
        if not text(t["access_token"],16384) or t["token_type"] != "Bearer" or not integer(t["expires_in"],1) or not strings(t["scopes"]) or t["scope"] != " ".join(t["scopes"]) or not text(t["tenant_id"]) or not text(t["subject"]): _fail()
        try:
            if datetime.fromisoformat(t["expires_at"].replace("Z", "+00:00")) <= datetime.now(timezone.utc): _fail()
        except (ValueError, TypeError, AttributeError): _fail()
        requested = (request.get("scope") or "").split()
        if requested and not set(t["scopes"]).issubset(requested): _fail()
        tenant(t["tenant_id"]); equal(t["subject"], options.get("expected_subject_id")); equal(t["subject"], agent_subject)
    elif operation == "introspectToken":
        if type(o.get("active")) is not bool: _fail()
        if o["active"]:
            fields(o, ["sub", "tenant_id", "exp", "scopes", "roles"])
            if not text(o["sub"]) or not text(o["tenant_id"]) or not integer(o["exp"],1) or o["exp"] <= time.time() or not strings(o["scopes"]) or not strings(o["roles"]): _fail()
            tenant(o["tenant_id"]); equal(o["sub"],options.get("expected_subject_id")); equal(o.get("app"),options.get("expected_application_id"))
        elif any(k in o for k in ("sub", "tenant_id", "exp", "scopes", "roles")): _fail()
    elif operation == "verifyTransactionReceipt":
        fields(o, ["valid", "status", "detail"])
        if type(o["valid"]) is not bool or o["status"] not in ("Valid", "SignatureInvalid", "UnknownSigningKey", "SignedOutsideKeyLifetime", "Malformed") or o["valid"] != (o["status"] == "Valid") or (o["detail"] is not None and not isinstance(o["detail"],str)): _fail()
    elif operation == "revokeToken":
        if o.get("status") != "revoked": _fail()
    elif operation in ("createTransaction", "getTransaction", "getTransactionReceipt"):
        transaction(o)
        if operation != "createTransaction": equal(o["transactionId"], segments[1])
        else:
            equal(o["declaredAction"],request["declaredAction"])
            if request.get("subjectPrincipalId"): equal(o.get("subjectPrincipalId"),request["subjectPrincipalId"])
        if operation == "getTransactionReceipt":
            fields(o, ["eventChainRoot", "issuedAtUtc", "signingKid", "algorithm", "signature"])
            if not all(text(o[k],32768) for k in ["eventChainRoot", "issuedAtUtc", "signingKid", "algorithm", "signature"]): _fail()
    elif operation == "getTransactionEvents":
        if not isinstance(value,list) or not all(integer(v.get("sequence"),1) and text(v.get("eventType")) and text(v.get("status")) and text(v.get("eventHash")) for v in value): _fail()
    elif operation == "registerAgent":
        fields(o, ["agent", "credentialId", "agentKey"]); agent(o["agent"])
        if not text(o["credentialId"]) or not text(o["agentKey"],16384) or not o["agentKey"].startswith(o["agent"]["agentId"]+":"): _fail()
        if request.get("applicationId"): equal(o["agent"]["applicationId"],request["applicationId"])
        if request.get("scopes") and not set(o["agent"]["scopes"]).issubset(request["scopes"]): _fail()
    elif operation == "listAgents":
        if not isinstance(value,list): _fail()
        for v in value: agent(v)
    elif operation == "revokeAgent":
        agent(o); equal(o["agentId"],segments[1])
        if o["status"] != "Revoked": _fail()
    elif operation == "bindProvider":
        if not text(o.get("bindingId")) or not strings(o.get("allowedModelIds")) or "apiKey" in o: _fail()
        equal(o.get("agentPrincipalId"),segments[1]); equal(o.get("providerId"),request["providerId"])
        if request.get("allowedModelIds") is not None and not set(o["allowedModelIds"]).issubset(request["allowedModelIds"]): _fail()
    elif operation == "invokeProvider":
        for k in ("transactionId", "providerId", "modelId"): equal(o.get(k),request[k])
        if not text(o.get("invocationId")) or not text(o.get("agentPrincipalId")) or type(o.get("succeeded")) is not bool or type(o.get("errorRetryable")) is not bool or (o["succeeded"] and o.get("errorKind") is not None) or (not o["succeeded"] and not text(o.get("errorKind"))): _fail()
    elif operation == "sendAgentMessage":
        equal(o.get("transactionId"),request["transactionId"]); envelope=obj(o.get("envelope"));h=obj(envelope.get("header"))
        for actual,expected in [(h.get("transactionId"),request["transactionId"]),(h.get("recipientPrincipalId"),request["recipientAgentId"]),(h.get("action"),request["action"])]: equal(actual,expected)
        if not text(envelope.get("envelopeId")) or not all(text(envelope.get(k),262144) for k in ("kemCiphertext", "aeadNonce", "ciphertext", "tag", "signature")): _fail()
    elif operation == "receiveAgentMessage":
        equal(o.get("transactionId"),request["transactionId"])
        if not text(o.get("senderAgentId")) or not text(o.get("action")) or not isinstance(o.get("payload"),str): _fail()
        header=request.get("envelope",{}).get("header")
        if header:
            equal(o["action"],header.get("action"));equal(o["senderAgentId"],header.get("senderPrincipalId"))
    elif operation == "scanIdentity":
        equal(o.get("subjectId"),segments[2]);graph_binding(o.get("graph"),segments[2]);graph_binding(o.get("exposure"),segments[2])
        equal(o["exposure"]["graphId"],o["graph"]["graphId"])
    elif operation == "getExposureSummary": graph_binding(o,segments[2])
    elif operation == "getIdentityGraph":
        graph_binding(o,segments[2])
        if not text(o.get("graphId")) or not isinstance(o.get("nodes"),list) or not isinstance(o.get("edges"),list): _fail()
        obj(o.get("scores"))
    elif operation == "performAction": equal(o.get("subjectId"),request["subjectId"])
    elif operation == "reverseAction": equal(o.get("actionId"),segments[2])
    elif operation == "getActionHistory":
        if not isinstance(value,list): _fail()
        for v in value: equal(obj(v).get("subjectId"),segments[3])
    elif operation == "listProviders":
        if not isinstance(value,list) or not all(text(obj(v).get("providerId")) for v in value): _fail()

_ENUMS=dict(nodeType=["Platform","Developer","DeveloperKey","Application","Environment","User","Device","Credential","Challenge","Token","AuditAnchor","PolicyScope","ExternalService"],edgeType=["Owns","Issued","Registered","BelongsTo","AuthorizedFor","ScopedTo","Uses","PresentedBy","DerivedFrom","ApprovedBy","RevokedBy","AnchoredBy","ConnectedTo","ObservedOn"],category=["WeakConnection","UnknownConnection","StaleCredential","HighRiskLinkage"],severity=["Low","Medium","High"],actionType=["LockIdentity","DisconnectService","VerifyConnection","RequestClarity"],actionStatus=["Completed","Reversed"])
def enum_name(kind,value):
 names=_ENUMS[kind]
 if type(value) is int and 1<=value<=len(names):return names[value-1]
 if isinstance(value,str) and value in names:return value
 _fail()
def request_body(operation,value):
 if operation!="performAction":return value
 return value|dict(actionType=_ENUMS["actionType"].index(enum_name("actionType",value.get("actionType")))+1)
def normalize_identity(operation,value):
 def action(v):
  v["actionType"]=enum_name("actionType",v.get("actionType"));v["status"]=enum_name("actionStatus",v.get("status"))
 def graph(v):
  for n in v.get("nodes",[]):n["nodeType"]=enum_name("nodeType",n.get("nodeType"))
  for e in v.get("edges",[]):e["edgeType"]=enum_name("edgeType",e.get("edgeType"))
 def exposure(v):
  for f in v.get("findings",[]):
   f["category"]=enum_name("category",f.get("category"));f["severity"]=enum_name("severity",f.get("severity"))
 if operation=="scanIdentity":
  graph(value["graph"]);exposure(value["exposure"])
  for a in value.get("actionHistory",[]):action(a)
 elif operation=="getIdentityGraph":graph(value)
 elif operation=="getExposureSummary":exposure(value)
 elif operation=="getActionHistory":
  for a in value:action(a)
 elif operation in ("performAction","reverseAction"):action(value)
 return value
