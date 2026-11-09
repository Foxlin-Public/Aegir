from __future__ import annotations

import json
from dataclasses import asdict
from typing import Callable
from urllib import parse, request
import threading
import re
from ._legacy import OwnedTransport, LegacyFailure, strict_json, safe_value, validate_response, request_body as legacy_request_body, normalize_identity

from .errors import AegirSecurityError
from .models import ExposureSummary, IdentityActionRecord, IdentityGraphSnapshot, PerformIdentityActionRequest, ScanIdentityResult


Transport = Callable[[str, str, dict[str, str], str | None], tuple[int, object]]


class AegirDiagnosticsHooks:
    def __init__(self, *, log=None, metric=None, trace=None) -> None:
        self.log = log
        self.metric = metric
        self.trace = trace


class AegirSecurityClient:
    __slots__ = ("_base_url", "_config_key", "_developer_key", "_access_token", "_transport",
                 "_native", "_diagnostics_hooks", "_options", "_closed", "_state_lock")
    def __init__(
        self,
        *,
        base_url: str,
        config_key: str | None = None,
        developer_key: str | None = None,
        access_token: str | None = None,
        transport: Transport | None = None,
        diagnostics_hooks: AegirDiagnosticsHooks | None = None,
        allow_trusted_custom_transport: bool = False,
        timeout_seconds: float = 10,
        cancel_event: threading.Event | None = None,
        certificate_sha256: str | None = None,
        expected_tenant_id: str | None = None,
        expected_application_id: str | None = None,
        expected_subject_id: str | None = None,
    ) -> None:
        try:
            if transport is not None and allow_trusted_custom_transport is not True:
                raise LegacyFailure("invalid_configuration")
            self._native = OwnedTransport(base_url, timeout_seconds, certificate_sha256, cancel_event)
            self._options = dict(expected_tenant_id=expected_tenant_id, expected_application_id=expected_application_id,
                                 expected_subject_id=expected_subject_id)
            for value in self._options.values():
                if value is not None and (not isinstance(value,str) or not value.strip() or len(value)>512):
                    raise LegacyFailure("invalid_configuration")
            for value in (developer_key, access_token):
                if value is not None and (not isinstance(value,str) or not value or len(value)>16384 or re.search(r"[\r\n\0]",value)):
                    raise LegacyFailure("invalid_configuration")
        except Exception:
            raise ValueError("Invalid Aegir client configuration.") from None
        self._base_url = self._native.base_url
        self._config_key = config_key # Deprecated input is never transmitted on identity routes.
        self._developer_key, self._access_token = developer_key, access_token
        self._transport = transport
        self._diagnostics_hooks = diagnostics_hooks
        self._closed = False
        self._state_lock = threading.RLock()

    def __repr__(self):
        return f"AegirSecurityClient(closed={self._closed})"

    def __getstate__(self):
        raise TypeError("Aegir clients containing credentials are not serializable.")

    def cancel_pending(self):
        """Abort owned active calls. Later calls remain permitted until close."""
        self._native.cancel_pending()

    def close(self):
        """Permanently close this client; no later credential state update is allowed."""
        with self._state_lock:
            self._closed = True
            self._access_token = self._developer_key = None
            self._native.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    def getToken(self, scope: str | None = None) -> dict:
        """Exchange the configured developer key for a signed access token.

        Beta-1 SDKs could call the identity-security operations but had no way to obtain,
        inspect or revoke a credential. ``scope`` narrows the grant; it can never widen it.
        """
        body = json.dumps({"grantType": "developer_key", "scope": scope})
        return self._request_json("getToken", "/token", method="POST", body=body)

    def useNarrowedToken(self, scope: str) -> dict:
        """Exchange the developer key for a scope-narrowed token and use it from here on.

        Prefer this in long-lived processes: the developer key is presented once rather than
        on every request, and the resulting credential carries only the scopes asked for.
        """
        token = self.getToken(scope)
        with self._state_lock:
            if self._closed:
                raise AegirSecurityError("Aegir client is closed.",0,"transport_error",None,None)
            self._access_token = token["access_token"]
        return token

    def useAgentKey(self, agentKey: str, scope: str | None = None) -> dict:
        """Exchange an ``agentId:secret`` pair for an agent token and use it from here on.

        The resulting token names the agent as the acting principal. Every capability below
        that is agent-scoped reads that identity from the token, never from a request body.
        """
        token = self._request_json(
            "useAgentKey",
            "/token",
            method="POST",
            body=json.dumps({"grantType": "agent_key", "scope": scope}),
            extra_headers={"X-Aegir-Agent-Key": agentKey},
        )
        with self._state_lock:
            if self._closed:
                raise AegirSecurityError("Aegir client is closed.",0,"transport_error",None,None)
            self._access_token = token["access_token"]
        return token

    def introspectToken(self, token: str) -> dict:
        """Check whether a token is currently usable. Returns ``{"active": False}`` if not."""
        return self._request_json(
            "introspectToken", "/introspect", method="POST", body=json.dumps({"token": token})
        )

    def revokeToken(self, token: str, reason: str | None = None) -> None:
        """Revoke a token. Idempotent, and does not report whether the token was known."""
        self._request_json(
            "revokeToken",
            "/token/revoke",
            method="POST",
            body=json.dumps({"token": token, "reason": reason}),
        )

    def scanIdentity(self, subjectId: str) -> ScanIdentityResult:
        return _model(ScanIdentityResult.from_json,self._request_json("scanIdentity", f"/security/scan/{parse.quote(subjectId, safe='')}"))

    def getIdentityGraph(self, subjectId: str) -> IdentityGraphSnapshot:
        return _model(IdentityGraphSnapshot.from_json,self._request_json("getIdentityGraph", f"/security/graphs/{parse.quote(subjectId, safe='')}"))

    def getIdentityGraphJson(self, subjectId: str) -> str:
        graph = self.getIdentityGraph(subjectId)
        return json.dumps(asdict(graph))

    def getExposureSummary(self, subjectId: str) -> ExposureSummary:
        return _model(ExposureSummary.from_json,self._request_json("getExposureSummary", f"/security/exposure/{parse.quote(subjectId, safe='')}"))

    def performAction(self, action: PerformIdentityActionRequest) -> IdentityActionRecord:
        return _model(IdentityActionRecord.from_json,
            self._request_json("performAction", "/security/actions", method="POST", body=json.dumps(action.to_json()))
        )

    def reverseAction(self, actionId: str, reason: str | None = None) -> IdentityActionRecord:
        suffix = f"?reason={parse.quote(reason, safe='')}" if reason else ""
        return _model(IdentityActionRecord.from_json,
            self._request_json("reverseAction", f"/security/actions/{parse.quote(actionId, safe='')}/reverse{suffix}", method="POST")
        )

    def getActionHistory(self, subjectId: str) -> list[IdentityActionRecord]:
        payload = self._request_json("getActionHistory", f"/security/actions/history/{parse.quote(subjectId, safe='')}")
        return [_model(IdentityActionRecord.from_json,item) for item in payload]

    # --- Canonical transactions --------------------------------------------------------
    #
    # A transaction is opened before the protected operation, so a refused or abandoned
    # attempt is as auditable as a successful one. Nothing below opens one implicitly.

    def createTransaction(
        self,
        declaredAction: str,
        *,
        targetResourceId: str | None = None,
        subjectPrincipalId: str | None = None,
        externalCorrelationId: str | None = None,
        lifetimeMinutes: int | None = None,
    ) -> dict:
        """Open a transaction. Requires ``transaction:write``."""
        return self._request_json(
            "createTransaction",
            "/transactions",
            method="POST",
            body=json.dumps(
                {
                    "declaredAction": declaredAction,
                    "targetResourceId": targetResourceId,
                    "subjectPrincipalId": subjectPrincipalId,
                    "externalCorrelationId": externalCorrelationId,
                    "lifetimeMinutes": lifetimeMinutes,
                }
            ),
        )

    def getTransaction(self, transactionId: str) -> dict:
        """Read a transaction. Requires ``transaction:read``."""
        return self._request_json(
            "getTransaction", f"/transactions/{parse.quote(transactionId, safe='')}"
        )

    def getTransactionEvents(self, transactionId: str) -> list[dict]:
        """Read a transaction's hash-chained event history. Requires ``transaction:read``."""
        return self._request_json(
            "getTransactionEvents", f"/transactions/{parse.quote(transactionId, safe='')}/events"
        )

    def getTransactionReceipt(self, transactionId: str) -> dict:
        """Issue a signed receipt for a transaction. Requires ``transaction:read``.

        Audit authority is deliberately narrow: it proves what Aegir decided and did. It does
        not resolve an opaque principal to a person, and it does not decrypt anything.
        """
        return self._request_json(
            "getTransactionReceipt", f"/transactions/{parse.quote(transactionId, safe='')}/receipt"
        )

    def verifyTransactionReceipt(self, receipt: dict) -> dict:
        """Verify a receipt, including whether its key was valid when it signed."""
        return self._request_json(
            "verifyTransactionReceipt",
            "/transactions/receipt/verify",
            method="POST",
            body=json.dumps({"receipt": receipt}),
        )

    # --- AI agent identity ---------------------------------------------------------------

    def registerAgent(
        self,
        displayName: str,
        *,
        providerId: str | None = None,
        modelId: str | None = None,
        applicationId: str | None = None,
        scopes: list[str] | None = None,
        lifetimeMinutes: int | None = None,
    ) -> dict:
        """Register an agent and return its credential. Requires ``agent:write``.

        ``agentKey`` comes back once and never again. ``agent:write`` is not grantable to an
        agent, so an agent can never register further agents.
        """
        return self._request_json(
            "registerAgent",
            "/agents",
            method="POST",
            body=json.dumps(
                {
                    "displayName": displayName,
                    "providerId": providerId,
                    "modelId": modelId,
                    "applicationId": applicationId,
                    "scopes": scopes,
                    "lifetimeMinutes": lifetimeMinutes,
                }
            ),
        )

    def listAgents(self) -> list[dict]:
        """List agents owned by the caller's developer account. Requires ``agent:read``."""
        return self._request_json("listAgents", "/agents")

    def revokeAgent(self, agentId: str) -> dict:
        """Revoke an agent. Requires ``agent:write``."""
        return self._request_json(
            "revokeAgent", f"/agents/{parse.quote(agentId, safe='')}/revoke", method="POST"
        )

    # --- Provider invocation ---------------------------------------------------------------

    def listProviders(self) -> list[dict]:
        """List providers this deployment can invoke. Requires ``agent:read``."""
        return self._request_json("listProviders", "/providers")

    def bindProvider(
        self,
        agentId: str,
        providerId: str,
        apiKey: str,
        *,
        allowedModelIds: list[str] | None = None,
    ) -> dict:
        """Bind an agent to a vendor credential. Requires ``agent:write``.

        The key is encrypted at rest and never returned. Naming ``allowedModelIds`` narrows the
        agent to the models its purpose requires.
        """
        return self._request_json(
            "bindProvider",
            f"/agents/{parse.quote(agentId, safe='')}/providers",
            method="POST",
            body=json.dumps(
                {"providerId": providerId, "apiKey": apiKey, "allowedModelIds": allowedModelIds}
            ),
        )

    def invokeProvider(
        self,
        transactionId: str,
        providerId: str,
        modelId: str,
        messages: list[dict],
        *,
        maxOutputTokens: int | None = None,
        temperature: float | None = None,
    ) -> dict:
        """Invoke a model provider as the authenticated agent. Requires ``agent:invoke``.

        A vendor failure comes back as ``succeeded: False`` with a normalized ``errorKind``
        rather than an exception, so a failed call is recorded exactly like a successful one.
        """
        return self._request_json(
            "invokeProvider",
            "/ai/invocations",
            method="POST",
            body=json.dumps(
                {
                    "transactionId": transactionId,
                    "providerId": providerId,
                    "modelId": modelId,
                    "messages": messages,
                    "maxOutputTokens": maxOutputTokens,
                    "temperature": temperature,
                }
            ),
        )

    # --- Protected agent-to-agent messaging -------------------------------------------------

    def sendAgentMessage(
        self, transactionId: str, recipientAgentId: str, action: str, payload: str
    ) -> dict:
        """Protect a payload to another agent, bound to a transaction. Requires ``agent:message``.

        ``payload`` is base64. The returned envelope is not transferable: moving it to another
        transaction, sender, recipient or action makes it fail validation.
        """
        return self._request_json(
            "sendAgentMessage",
            "/ai/messages",
            method="POST",
            body=json.dumps(
                {
                    "transactionId": transactionId,
                    "recipientAgentId": recipientAgentId,
                    "action": action,
                    "payload": payload,
                }
            ),
        )

    def receiveAgentMessage(self, message: dict) -> dict:
        """Open a protected message addressed to the authenticated agent."""
        return self._request_json(
            "receiveAgentMessage",
            "/ai/messages/receive",
            method="POST",
            body=json.dumps(message),
        )

    def _request_json(
        self,
        operation: str,
        path: str,
        *,
        method: str = "GET",
        body: str | None = None,
        extra_headers: dict[str, str] | None = None,
    ):
        try:
            return self._native.run(lambda lifetime: self._request_core(operation, path, method=method,
                body=body, extra_headers=extra_headers, lifetime=lifetime))
        except AegirSecurityError:
            raise
        except Exception:
            raise AegirSecurityError("Aegir request failed or was cancelled.",0,"transport_error",None,None) from None

    def _request_core(self, operation, path, *, method, body, extra_headers, lifetime):
        headers = {"Accept": "application/json"}
        if body is not None: headers["Content-Type"] = "application/json"
        with self._state_lock:
            if self._closed:
                raise AegirSecurityError("Aegir client is closed.",0,"transport_error",None,None)
            if not (extra_headers and "X-Aegir-Agent-Key" in extra_headers):
                if self._access_token: headers["Authorization"] = f"Bearer {self._access_token}"
                elif self._developer_key: headers["X-Aegir-Developer-Key"] = self._developer_key
            credentials = [v for v in (self._access_token,self._developer_key,self._config_key) if isinstance(v,str) and v]
        if extra_headers:
            headers.update(extra_headers); credentials.extend(v for v in extra_headers.values() if isinstance(v,str) and v)
        # Preserve full credentials and every nonempty id:secret component, longest first.
        secrets = sorted({part for value in credentials for part in (value, *value.split(":")) if part}, key=len, reverse=True)
        try: request_body = strict_json(body) if body is not None else {}
        except Exception:
            raise AegirSecurityError("Invalid Aegir request.",0,"invalid_request",None,None) from None
        def collect(v):
            if isinstance(v,str): secrets.append(v)
            elif isinstance(v,dict):
                for x in v.values(): collect(x)
            elif isinstance(v,list):
                for x in v: collect(x)
        collect(request_body)
        self._emit_trace(dict(traceName="request.start",operation=operation,tracePhase="request.start",occurredAtUtc=_utc_now(),correlationId=None,metadata={"method":method}),lifetime)
        self._emit_log(dict(level="information",eventName="request.start",message=f"Starting {operation}.",operation=operation,correlationId=None,occurredAtUtc=_utc_now(),metadata={"method":method}),lifetime)
        try:
            wire_body=json.dumps(legacy_request_body(operation,request_body)) if body is not None else None
            status,payload = self._native.call(f"{self._base_url}/v1{path}",method,headers,wire_body,self._transport,lifetime)
            if type(status) is not int or not 100 <= status <= 599: raise LegacyFailure("invalid_server_response")
        except Exception:
            raise AegirSecurityError("Aegir transport request failed or was cancelled.",0,"transport_error",None,None) from None
        safe_body = safe_value(payload,secrets)
        correlation_id = safe_body.get("correlationId") if isinstance(safe_body,dict) else None
        if not isinstance(correlation_id,str) or not re.fullmatch(r"[A-Za-z0-9_.:-]{1,128}",correlation_id): correlation_id=None
        code = _resolve_error_code(status,safe_body)
        if not re.fullmatch(r"[a-z][a-z0-9_.:-]{0,127}",code): code="unknown_error"
        self._emit_metric(dict(metricName="aegir.client.request.duration",value=0,unit="ms",observedAtUtc=_utc_now(),dimensions={"operation":operation,"status":str(status),"errorCode":code}),lifetime)
        if status < 200 or status >= 300:
            raise AegirSecurityError(f"Aegir request failed with status {status}.",status,code,correlation_id,safe_body)
        try:
            if status != (201 if operation in ("createTransaction","registerAgent") else 200): raise LegacyFailure("invalid_server_response")
            key=headers.get("X-Aegir-Agent-Key")
            agent_subject=key.split(":",1)[0] if key else None
            if key and (":" not in key or not agent_subject or not key.split(":",1)[1]): raise LegacyFailure("invalid_request")
            validate_response(operation,path,payload,request_body,self._options,agent_subject)
            normalize_identity(operation,payload)
            with self._state_lock:
                if self._closed: raise LegacyFailure("client_closed")
        except Exception:
            raise AegirSecurityError("Aegir returned an invalid or mismatched response.",status,"transport_error",correlation_id,None) from None
        self._emit_log(dict(level="information",eventName="request.complete",message=f"Completed {operation}.",operation=operation,correlationId=correlation_id,occurredAtUtc=_utc_now(),metadata={"status":str(status)}),lifetime)
        self._emit_trace(dict(traceName="request.complete",operation=operation,tracePhase="request.complete",occurredAtUtc=_utc_now(),correlationId=correlation_id,metadata={"status":str(status)}),lifetime)
        with self._state_lock:
            if self._closed: raise AegirSecurityError("Aegir client is closed.",0,"transport_error",None,None)
        return payload

    def _emit_log(self, entry, lifetime) -> None:
        self._native.observe(self._diagnostics_hooks.log if self._diagnostics_hooks else None, entry, lifetime)

    def _emit_metric(self, event, lifetime) -> None:
        self._native.observe(self._diagnostics_hooks.metric if self._diagnostics_hooks else None, event, lifetime)

    def _emit_trace(self, event, lifetime) -> None:
        self._native.observe(self._diagnostics_hooks.trace if self._diagnostics_hooks else None, event, lifetime)

    @staticmethod
    def _default_transport(url: str, method: str, headers: dict[str,str], body: str | None) -> tuple[int,object]:
        """Retained private helper; actual clients own and dispose their native transport."""
        native=OwnedTransport(url.split("/v1",1)[0],10)
        try: return native.call(url,method,headers,body)
        finally: native.close()


def _utc_now() -> str:
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _resolve_error_code(status: int, payload) -> str:
    if isinstance(payload, dict):
        candidate = payload.get("code") or payload.get("error")
        if isinstance(candidate, str) and candidate:
            return candidate

    if status == 400:
        return "invalid_request"
    if status == 401:
        return "unauthorized"
    if status == 403:
        return "forbidden"
    if status == 404:
        return "not_found"
    if status == 409:
        return "conflict"
    if status == 429:
        return "rate_limited"
    if status >= 500:
        return "server_error"
    return "unknown_error"


def _model(factory,value):
    try: return factory(value)
    except Exception:
        raise AegirSecurityError("Aegir returned an invalid identity model.",200,"transport_error",None,None) from None
