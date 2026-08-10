from __future__ import annotations

import json
from dataclasses import asdict
from typing import Callable
from urllib import parse, request
from urllib.error import HTTPError

from .errors import AegirSecurityError
from .models import ExposureSummary, IdentityActionRecord, IdentityGraphSnapshot, PerformIdentityActionRequest, ScanIdentityResult


Transport = Callable[[str, str, dict[str, str], str | None], tuple[int, object]]


class AegirDiagnosticsHooks:
    def __init__(self, *, log=None, metric=None, trace=None) -> None:
        self.log = log
        self.metric = metric
        self.trace = trace


class AegirSecurityClient:
    def __init__(
        self,
        *,
        base_url: str,
        config_key: str | None = None,
        developer_key: str | None = None,
        access_token: str | None = None,
        transport: Transport | None = None,
        diagnostics_hooks: AegirDiagnosticsHooks | None = None,
    ) -> None:
        if not base_url or not base_url.strip():
            raise ValueError("A base_url is required.")

        self._base_url = base_url.rstrip("/")
        self._config_key = config_key
        self._developer_key = developer_key
        self._access_token = access_token
        self._transport = transport or self._default_transport
        self._diagnostics_hooks = diagnostics_hooks

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
        return ScanIdentityResult.from_json(self._request_json("scanIdentity", f"/security/scan/{parse.quote(subjectId, safe='')}"))

    def getIdentityGraph(self, subjectId: str) -> IdentityGraphSnapshot:
        return IdentityGraphSnapshot.from_json(self._request_json("getIdentityGraph", f"/security/graphs/{parse.quote(subjectId, safe='')}"))

    def getIdentityGraphJson(self, subjectId: str) -> str:
        graph = self.getIdentityGraph(subjectId)
        return json.dumps(asdict(graph))

    def getExposureSummary(self, subjectId: str) -> ExposureSummary:
        return ExposureSummary.from_json(self._request_json("getExposureSummary", f"/security/exposure/{parse.quote(subjectId, safe='')}"))

    def performAction(self, action: PerformIdentityActionRequest) -> IdentityActionRecord:
        return IdentityActionRecord.from_json(
            self._request_json("performAction", "/security/actions", method="POST", body=json.dumps(action.to_json()))
        )

    def reverseAction(self, actionId: str, reason: str | None = None) -> IdentityActionRecord:
        suffix = f"?reason={parse.quote(reason, safe='')}" if reason else ""
        return IdentityActionRecord.from_json(
            self._request_json("reverseAction", f"/security/actions/{parse.quote(actionId, safe='')}/reverse{suffix}", method="POST")
        )

    def getActionHistory(self, subjectId: str) -> list[IdentityActionRecord]:
        payload = self._request_json("getActionHistory", f"/security/actions/history/{parse.quote(subjectId, safe='')}")
        return [IdentityActionRecord.from_json(item) for item in payload]

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
        headers = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self._config_key:
            headers["X-Aegir-Config-Key"] = self._config_key

        # A bearer token takes precedence: once one has been obtained there is no reason to
        # keep presenting the long-lived developer key on every request.
        if self._access_token:
            headers["Authorization"] = f"Bearer {self._access_token}"
        elif self._developer_key:
            headers["X-Aegir-Developer-Key"] = self._developer_key

        if extra_headers:
            headers.update(extra_headers)

        self._emit_trace({
            "traceName": "request.start",
            "operation": operation,
            "tracePhase": "request.start",
            "occurredAtUtc": _utc_now(),
            "correlationId": None,
            "metadata": {"path": path, "method": method},
        })
        self._emit_log({
            "level": "information",
            "eventName": "request.start",
            "message": f"Starting {operation}.",
            "operation": operation,
            "correlationId": None,
            "occurredAtUtc": _utc_now(),
            "metadata": {"path": path, "method": method},
        })

        status, payload = self._transport(f"{self._base_url}/v1{path}", method, headers, body)
        correlation_id = payload.get("correlationId") if isinstance(payload, dict) else None
        code = _resolve_error_code(status, payload)
        self._emit_metric({
            "metricName": "aegir.client.request.duration",
            "value": 0,
            "unit": "ms",
            "observedAtUtc": _utc_now(),
            "dimensions": {"operation": operation, "status": str(status), "errorCode": code},
        })
        if status < 200 or status >= 300:
            self._emit_log({
                "level": "error",
                "eventName": "request.error",
                "message": f"Aegir request failed with status {status}.",
                "operation": operation,
                "correlationId": correlation_id,
                "occurredAtUtc": _utc_now(),
                "metadata": {"status": str(status), "errorCode": code},
            })
            self._emit_trace({
                "traceName": "request.error",
                "operation": operation,
                "tracePhase": "request.error",
                "occurredAtUtc": _utc_now(),
                "correlationId": correlation_id,
                "metadata": {"status": str(status), "errorCode": code},
            })
            raise AegirSecurityError(f"Aegir request failed with status {status}.", status, code, correlation_id, payload)
        self._emit_log({
            "level": "information",
            "eventName": "request.complete",
            "message": f"Completed {operation}.",
            "operation": operation,
            "correlationId": correlation_id,
            "occurredAtUtc": _utc_now(),
            "metadata": {"status": str(status)},
        })
        self._emit_trace({
            "traceName": "request.complete",
            "operation": operation,
            "tracePhase": "request.complete",
            "occurredAtUtc": _utc_now(),
            "correlationId": correlation_id,
            "metadata": {"status": str(status)},
        })
        return payload

    def _emit_log(self, entry) -> None:
        if self._diagnostics_hooks and self._diagnostics_hooks.log:
            self._diagnostics_hooks.log(entry)

    def _emit_metric(self, event) -> None:
        if self._diagnostics_hooks and self._diagnostics_hooks.metric:
            self._diagnostics_hooks.metric(event)

    def _emit_trace(self, event) -> None:
        if self._diagnostics_hooks and self._diagnostics_hooks.trace:
            self._diagnostics_hooks.trace(event)

    @staticmethod
    def _default_transport(url: str, method: str, headers: dict[str, str], body: str | None) -> tuple[int, object]:
        data = body.encode("utf-8") if body is not None else None
        req = request.Request(url, data=data, headers=headers, method=method)
        try:
            with request.urlopen(req) as response:
                text = response.read().decode("utf-8")
                return response.status, json.loads(text) if text else None
        except HTTPError as ex:
            text = ex.read().decode("utf-8")
            try:
                parsed = json.loads(text) if text else None
            except json.JSONDecodeError:
                parsed = text
            return ex.code, parsed


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
