"""Foxlin Industries. Additive, unreleased protocol-v1 developer integration.

Events invalidate journal projections; they never grant authority. Execute uses a
second authoritative check before the host's commit callback, not a distributed
transaction. See INTEGRATION.md for persistence and recovery responsibilities.
"""
from __future__ import annotations
import hashlib
import http.client
import json
from pathlib import Path
import socket
import sqlite3
import ssl
import threading
import time
from datetime import datetime, timezone
from typing import Any, Callable, Protocol
from urllib.parse import urlsplit

EVENT_TYPES = frozenset(("granted", "revoked", "adminGranted", "adminRevoked",
    "permissionChanged", "licenseGranted", "licenseRevoked", "membershipChanged",
    "suspended", "restored", "groupPolicyChanged"))
_EVENT_FIELDS = frozenset(("protocolVersion", "transactionId", "eventId", "groupId",
                          "userId", "eventType", "groupVersion"))


class AegirIntegrationError(Exception):
    """A bounded machine-readable error with no server body or secret material."""
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class AegirMfaRequired(AegirIntegrationError):
    def __init__(self, challenge_id: str):
        self.challenge_id = challenge_id
        super().__init__("mfa_required")


def _text(value: Any, limit: int = 512) -> bool:
    return isinstance(value, str) and 0 < len(value.strip()) <= limit


def _integer(value: Any, minimum: int = 0) -> bool:
    return type(value) is int and minimum <= value <= 9007199254740991


def _object(value: Any) -> dict:
    if not isinstance(value, dict):
        raise AegirIntegrationError("invalid_server_response")
    return value


def _json(data: str) -> Any:
    depth, quoted, escaped = 0, False, False
    for char in data:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "{[":
            depth += 1
            if depth > 32:
                raise AegirIntegrationError("invalid_server_response")
        elif char in "}]":
            depth -= 1
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise AegirIntegrationError("invalid_server_response")
            result[key] = value
        return result
    try:
        return json.loads(data, object_pairs_hook=unique, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, UnicodeError, RecursionError):
        raise AegirIntegrationError("invalid_server_response") from None


def _event(value: Any) -> dict:
    v = _object(value)
    if set(v) != _EVENT_FIELDS or type(v.get("protocolVersion")) is not int or v.get("protocolVersion") != 1:
        raise AegirIntegrationError("unsupported_event_protocol")
    if not all(_text(v.get(k)) for k in ("transactionId", "eventId", "groupId", "eventType")) or not _integer(v.get("groupVersion"), 1):
        raise AegirIntegrationError("invalid_server_response")
    if v["userId"] is not None and not _text(v["userId"]):
        raise AegirIntegrationError("invalid_server_response")
    return v


def _snapshot(value: Any) -> dict:
    v = _object(value)
    if not _text(v.get("snapshotId")) or not isinstance(v.get("groups"), list) or len(v["groups"]) > 100:
        raise AegirIntegrationError("invalid_server_response")
    groups = set()
    total = 0
    for group in v["groups"]:
        g = _object(group)
        if not _text(g.get("groupId")) or g["groupId"] in groups or not _integer(g.get("groupVersion")) or not isinstance(g.get("subjects"), list):
            raise AegirIntegrationError("invalid_server_response")
        groups.add(g["groupId"])
        subjects = set()
        for subject in g["subjects"]:
            s = _object(subject)
            if not _text(s.get("userId")) or s["userId"] in subjects or type(s.get("allowed")) is not bool or not _integer(s.get("authorizationEpoch")):
                raise AegirIntegrationError("invalid_server_response")
            subjects.add(s["userId"])
        total += len(g["subjects"])
    if total > 2000:
        raise AegirIntegrationError("invalid_server_response")
    return v


class AuthorizationJournal(Protocol):
    """Host adapters must atomically commit receipt/version/invalidation effects."""
    def apply(self, events: list[dict]) -> dict: ...
    def apply_snapshot(self, snapshot: dict) -> None: ...
    def set_connected(self, connected: bool) -> None: ...
    def inspect(self) -> dict: ...
    def close(self) -> None: ...


class SqliteAuthorizationJournal:
    """Local durable adapter; SQLite transactions own all journal effects.

    One file per stable server/organization/application stream. Never store
    credentials in this file. Restoring an older journal requires reconnect.
    """
    def __init__(self, path: str | Path, binding: str):
        if not _text(binding, 2048):
            raise AegirIntegrationError("invalid_configuration")
        self._lock = threading.RLock()
        self._closed = False
        self._db = sqlite3.connect(str(path), timeout=5, check_same_thread=False)
        self._db.execute("pragma journal_mode=WAL")
        self._db.execute("pragma synchronous=FULL")
        self._db.executescript("""
            create table if not exists aegir_meta(id integer primary key check(id=1),binding text not null,connected integer not null);
            create table if not exists aegir_receipts(event_id text primary key,payload text not null);
            create table if not exists aegir_versions(group_id text primary key,version integer not null);
            create table if not exists aegir_effects(event_id text primary key,event_type text not null);
            create table if not exists aegir_subjects(group_id text not null,user_id text not null,epoch integer not null,primary key(group_id,user_id));
        """)
        row = self._db.execute("select binding from aegir_meta where id=1").fetchone()
        if row and row[0] != binding:
            self._db.close()
            raise AegirIntegrationError("journal_binding_mismatch")
        with self._db:
            self._db.execute("insert into aegir_meta values(1,?,0) on conflict(id) do update set connected=0", (binding,))

    def _ready(self):
        if self._closed:
            raise AegirIntegrationError("disposed")

    def set_connected(self, connected: bool) -> None:
        with self._lock, self._db:
            self._ready()
            self._db.execute("update aegir_meta set connected=? where id=1", (int(connected),))

    def apply(self, events: list[dict]) -> dict:
        if not isinstance(events, list) or len(events) > 100:
            raise AegirIntegrationError("invalid_server_response")
        parsed = [_event(e) for e in events]
        if any(e["eventType"] not in EVENT_TYPES for e in parsed):
            return {"newEffects": 0, "requiresSnapshot": True}
        with self._lock:
            self._ready()
            self._db.execute("begin immediate")
            count = 0
            try:
                for e in parsed:
                    encoded = json.dumps(e, sort_keys=True, separators=(",", ":"))
                    prior_payload = self._db.execute("select payload from aegir_receipts where event_id=?", (e["eventId"],)).fetchone()
                    if prior_payload:
                        if prior_payload[0] != encoded:
                            raise AegirIntegrationError("event_identity_conflict")
                        continue
                    prior_row = self._db.execute("select version from aegir_versions where group_id=?", (e["groupId"],)).fetchone()
                    prior = prior_row[0] if prior_row else 0
                    if e["groupVersion"] > prior + 1:
                        self._db.rollback()
                        return {"newEffects": 0, "requiresSnapshot": True}
                    self._db.execute("insert into aegir_receipts values(?,?)", (e["eventId"], encoded))
                    if e["groupVersion"] < prior:
                        continue
                    self._db.execute("insert into aegir_versions values(?,?) on conflict(group_id) do update set version=max(version,excluded.version)", (e["groupId"], e["groupVersion"]))
                    self._db.execute("insert into aegir_effects values(?,?)", (e["eventId"], e["eventType"]))
                    self._db.execute("delete from aegir_subjects where group_id=?", (e["groupId"],))
                    count += 1
                self._db.commit()
                return {"newEffects": count, "requiresSnapshot": False}
            except BaseException:
                self._db.rollback()
                raise

    def apply_snapshot(self, snapshot: dict) -> None:
        s = _snapshot(snapshot)
        with self._lock:
            self._ready()
            self._db.execute("begin immediate")
            try:
                for group in s["groups"]:
                    row = self._db.execute("select version from aegir_versions where group_id=?", (group["groupId"],)).fetchone()
                    if row and group["groupVersion"] < row[0]:
                        raise AegirIntegrationError("snapshot_rollback")
                self._db.execute("delete from aegir_subjects")
                for group in s["groups"]:
                    self._db.execute("insert into aegir_versions values(?,?) on conflict(group_id) do update set version=max(version,excluded.version)", (group["groupId"], group["groupVersion"]))
                    for subject in group["subjects"]:
                        if subject["allowed"]:
                            self._db.execute("insert into aegir_subjects values(?,?,?)", (group["groupId"], subject["userId"], subject["authorizationEpoch"]))
                self._db.commit()
            except BaseException:
                self._db.rollback()
                raise

    def inspect(self) -> dict:
        with self._lock:
            self._ready()
            return {"connected": bool(self._db.execute("select connected from aegir_meta").fetchone()[0]),
                    "receipts": self._db.execute("select count(*) from aegir_receipts").fetchone()[0],
                    "effects": self._db.execute("select count(*) from aegir_effects").fetchone()[0],
                    "versions": dict(self._db.execute("select group_id,version from aegir_versions")),
                    "eventIds": [r[0] for r in self._db.execute("select event_id from aegir_receipts order by event_id")]}

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self.set_connected(False)
                self._db.close()
                self._closed = True


class _HttpsTransport:
    def __init__(self, base_url: str, certificate_sha256: str | None, timeout: float):
        if not isinstance(base_url, str) or any(c in base_url for c in "\\\r\n\t%"):
            raise AegirIntegrationError("invalid_configuration")
        u = urlsplit(base_url)
        if u.scheme != "https" or not u.hostname or u.username or u.password or u.query or u.fragment or not u.path.endswith("/"):
            raise AegirIntegrationError("invalid_configuration")
        try:
            self._port = u.port or 443
        except ValueError:
            raise AegirIntegrationError("invalid_configuration") from None
        self._host, self._prefix = u.hostname, u.path
        self._pin = None
        if certificate_sha256 is not None:
            if self._host not in ("localhost", "127.0.0.1", "::1") or len(certificate_sha256) != 64:
                raise AegirIntegrationError("invalid_configuration")
            try:
                self._pin = bytes.fromhex(certificate_sha256)
            except ValueError:
                raise AegirIntegrationError("invalid_configuration") from None
            if len(self._pin) != 32:
                raise AegirIntegrationError("invalid_configuration")
        self._timeout = timeout
        self._active: set[http.client.HTTPSConnection] = set()
        self._lock = threading.Lock()
        self._closed = False

    def request(self, path: str, body: dict | None = None, credential: str | None = None,
                cancel: threading.Event | None = None) -> tuple[int, Any]:
        if cancel and cancel.is_set():
            raise AegirIntegrationError("cancelled")
        context = ssl._create_unverified_context() if self._pin else ssl.create_default_context()
        conn = http.client.HTTPSConnection(self._host, self._port, timeout=self._timeout, context=context)
        finished = threading.Event()
        timed_out = threading.Event()
        def timeout_request():
            timed_out.set()
            try:
                active_socket = conn.sock
                if active_socket:
                    active_socket.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            conn.close()
        timer = threading.Timer(self._timeout, timeout_request)
        timer.daemon = True
        def cancellation():
            while not finished.wait(0.02):
                if cancel and cancel.is_set():
                    try:
                        active_socket = conn.sock
                        if active_socket:
                            active_socket.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass
                    conn.close()
                    return
        watcher = threading.Thread(target=cancellation, daemon=True) if cancel else None
        with self._lock:
            if self._closed:
                raise AegirIntegrationError("disposed")
            self._active.add(conn)
        try:
            timer.start()
            if watcher:
                watcher.start()
            conn.connect()
            if self._pin:
                actual = hashlib.sha256(conn.sock.getpeercert(binary_form=True)).digest()
                if actual != self._pin:
                    raise AegirIntegrationError("certificate_pin_mismatch")
            headers = {"Accept": "application/json"}
            if credential:
                headers["X-Aegir-Application-Key"] = credential
            data = json.dumps(body, separators=(",", ":")) if body is not None else None
            if data is not None:
                headers["Content-Type"] = "application/json"
            conn.request("POST" if body is not None else "GET", self._prefix + path, body=data, headers=headers)
            response = conn.getresponse()
            raw = response.read(2 * 1024 * 1024 + 1)
            if cancel and cancel.is_set():
                raise AegirIntegrationError("cancelled")
            if timed_out.is_set():
                raise AegirIntegrationError("deadline_exceeded")
            if 300 <= response.status < 400:
                raise AegirIntegrationError("redirect_rejected")
            if len(raw) > 2 * 1024 * 1024:
                raise AegirIntegrationError("invalid_server_response")
            if not raw:
                return response.status, None
            if response.getheader("Content-Type", "").split(";", 1)[0].strip().lower() != "application/json":
                raise AegirIntegrationError("invalid_server_response")
            return response.status, _json(raw.decode("utf-8", errors="strict"))
        except AegirIntegrationError:
            raise
        except (OSError, http.client.HTTPException, UnicodeError, ValueError):
            raise AegirIntegrationError("cancelled" if cancel and cancel.is_set() else "deadline_exceeded" if timed_out.is_set() else "authoritative_access_unavailable") from None
        finally:
            timer.cancel()
            finished.set()
            conn.close()
            if watcher:
                watcher.join(timeout=0.1)
            with self._lock:
                self._active.discard(conn)

    def close(self):
        with self._lock:
            self._closed = True
            for conn in list(self._active):
                try:
                    active_socket = conn.sock
                    if active_socket:
                        active_socket.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                conn.close()


class AegirIntegrationClient:
    """Owns safe HTTP transports and serializes polling/checks.

    Startup/disconnect require reconnect. A normal healthy poll never resets
    connectivity. Every protected operation still contacts canonical authority.
    """
    def __init__(self, *, api_base_url: str, web_base_url: str, application_credential: str,
                 organization_id: str, application_id: str, journal: AuthorizationJournal,
                 certificate_sha256: str | None = None, timeout_seconds: float = 15):
        if not _text(application_credential) or any(not 33 <= ord(c) <= 126 for c in application_credential) or not _text(organization_id, 256) or not _text(application_id, 256) or not (0 < timeout_seconds <= 120):
            raise AegirIntegrationError("invalid_configuration")
        self._api = _HttpsTransport(api_base_url, certificate_sha256, timeout_seconds)
        self._web = _HttpsTransport(web_base_url, certificate_sha256, timeout_seconds)
        self._credential = application_credential
        self.organization_id, self.application_id = organization_id, application_id
        self._journal, self._connected, self._disposed = journal, False, False
        self._lock = threading.RLock()
        self._journal.set_connected(False)
        self._lifetime = threading.Event()

    def _ready(self):
        if self._disposed:
            raise AegirIntegrationError("disposed")

    def _disconnect(self):
        self._connected = False
        self._journal.set_connected(False)

    def authenticate(self, username: str, password: str, *, challenge_id: str | None = None,
                     totp_code: str | None = None, cancel: threading.Event | None = None) -> dict:
        with self._lock:
            self._ready()
            if not _text(username, 320) or not isinstance(password, str) or not 0 < len(password) <= 2048 or (challenge_id is not None and not _text(challenge_id)) or (totp_code is not None and not _text(totp_code, 128)):
                raise AegirIntegrationError("invalid_authentication_request")
            body = {"username": username, "password": password, "organizationId": self.organization_id,
                    "applicationId": self.application_id, "challengeId": challenge_id, "totpCode": totp_code}
            status, value = self._web.request("account/organization-access", body, cancel=cancel)
            self._ready()
            if status == 400 and isinstance(value, dict) and value.get("error") == "mfa_required" and _text(value.get("challengeId")):
                raise AegirMfaRequired(value["challengeId"])
            if status != 200:
                raise AegirIntegrationError("authentication_denied")
            v = _object(value)
            if not {"accessToken", "expiresAtUtc", "organizationId", "applicationId", "subjectId", "authorizationEpoch"}.issubset(v) or not _text(v.get("accessToken")) or not _text(v.get("subjectId")) or v.get("organizationId") != self.organization_id or v.get("applicationId") != self.application_id or not _text(v.get("expiresAtUtc")) or not _integer(v.get("authorizationEpoch")):
                raise AegirIntegrationError("invalid_server_response")
            try:
                expiry = datetime.fromisoformat(v["expiresAtUtc"].replace("Z", "+00:00"))
                if expiry.tzinfo is None or expiry <= datetime.now(timezone.utc):
                    raise ValueError()
            except ValueError:
                raise AegirIntegrationError("invalid_server_response") from None
            return v

    def _request(self, path, body=None, cancel=None):
        status, value = self._api.request("v1/authorization/" + path, body, self._credential, cancel)
        self._ready()
        if status not in (200, 204):
            raise AegirIntegrationError("backend_credential_denied" if status in (401, 403) else "invalid_server_response")
        return value

    def _reconcile(self, cancel=None):
        self._disconnect()
        snapshot = _snapshot(self._request("snapshot", cancel=cancel))
        self._journal.apply_snapshot(snapshot)
        self._request("snapshot/ack", {"snapshotId": snapshot["snapshotId"]}, cancel)

    def _cycle(self, cancel=None, acknowledge=True):
        batch = _object(self._request("events?limit=100", cancel=cancel))
        if type(batch.get("requiresSnapshot")) is not bool or not isinstance(batch.get("events"), list) or len(batch["events"]) > 100 or not _integer(batch.get("retryAfterSeconds")):
            raise AegirIntegrationError("invalid_server_response")
        if batch["requiresSnapshot"]:
            self._reconcile(cancel)
            return {"reconciled": True, "newEffects": 0, "empty": False}
        if batch.get("reason") == "retry_backoff":
            return {"backoff": min(30, max(1, batch["retryAfterSeconds"])), "newEffects": 0, "empty": False}
        if not batch["events"]:
            return {"newEffects": 0, "empty": True}
        if not _text(batch.get("deliveryId")):
            raise AegirIntegrationError("invalid_server_response")
        result = self._journal.apply(batch["events"])
        if result["requiresSnapshot"]:
            self._reconcile(cancel)
            return {"reconciled": True, "newEffects": 0, "empty": False}
        if acknowledge:
            self._request("ack", {"deliveryId": batch["deliveryId"]}, cancel)
        else:
            self._disconnect()
        return {"newEffects": result["newEffects"], "empty": False, "acknowledged": acknowledge}

    def reconnect(self, *, cancel: threading.Event | None = None) -> dict:
        with self._lock:
            self._ready()
            self._disconnect()
            total = 0
            reconciled = False
            try:
                for _ in range(20):
                    result = self._cycle(cancel)
                    self._ready()
                    total += result["newEffects"]
                    if result.get("reconciled"):
                        reconciled = True
                    if result.get("backoff"):
                        deadline = time.monotonic() + result["backoff"]
                        while time.monotonic() < deadline:
                            if self._lifetime.wait(min(.02, max(0, deadline - time.monotonic()))):
                                raise AegirIntegrationError("disposed")
                            if cancel and cancel.is_set():
                                raise AegirIntegrationError("cancelled")
                    elif result["empty"]:
                        if not reconciled:
                            self._reconcile(cancel)
                            reconciled = True
                            continue
                        self._connected = True
                        self._journal.set_connected(True)
                        return {"connected": True, "newEffects": total}
                raise AegirIntegrationError("reconciliation_limit")
            except BaseException:
                self._disconnect()
                raise

    def poll(self, *, cancel: threading.Event | None = None, acknowledge: bool = True) -> dict:
        with self._lock:
            self._ready()
            if not self._connected:
                return self.reconnect(cancel=cancel)
            try:
                result = self._cycle(cancel, acknowledge)
                if result.get("reconciled"):
                    return self.reconnect(cancel=cancel)
                return dict(result, connected=self._connected)
            except BaseException:
                self._disconnect()
                raise

    @staticmethod
    def _denial(reason):
        return {"isAuthorized": False, "reason": reason, "applicationSubjectId": None,
                "authorizationEpoch": 0, "effectiveGroupIds": [], "permissions": []}

    def authorize(self, access_token: str, operation: str, *, cancel: threading.Event | None = None) -> dict:
        with self._lock:
            self._ready()
            if operation not in ("read", "write"):
                return self._denial("unsupported_operation")
            if cancel and cancel.is_set():
                raise AegirIntegrationError("cancelled")
            if not self._connected:
                return self._denial("event_reconciliation_required")
            try:
                status, value = self._api.request("v1/authorization/check", {"accessToken": access_token, "operation": operation}, self._credential, cancel)
                self._ready()
                v = _object(value)
                valid = ({"isAuthorized", "reason", "applicationSubjectId", "authorizationEpoch", "effectiveGroupIds", "permissions"}.issubset(v)
                         and status in (200, 403) and type(v.get("isAuthorized")) is bool and status == (200 if v["isAuthorized"] else 403) and _text(v.get("reason"))
                         and (v.get("applicationSubjectId") is None or _text(v.get("applicationSubjectId")))
                         and _integer(v.get("authorizationEpoch")) and isinstance(v.get("effectiveGroupIds"), list)
                         and len(v["effectiveGroupIds"]) <= 100 and all(_text(g) for g in v["effectiveGroupIds"])
                         and len(set(v["effectiveGroupIds"])) == len(v["effectiveGroupIds"]) and isinstance(v.get("permissions"), list)
                         and len(v["permissions"]) <= 2 and all(p in ("read", "write") for p in v["permissions"])
                         and len(set(v["permissions"])) == len(v["permissions"]))
                if not valid or (v["isAuthorized"] and (status != 200 or v["reason"] != "authorized" or not _text(v.get("applicationSubjectId")) or not v["effectiveGroupIds"] or operation not in v["permissions"])):
                    raise AegirIntegrationError("invalid_authority_response")
                if not v["isAuthorized"] and v["reason"] == "event_reconciliation_required":
                    self._disconnect()
                return v
            except AegirIntegrationError as error:
                self._disconnect()
                if error.code in ("cancelled", "disposed"):
                    raise
                return self._denial(error.code)

    def execute(self, access_token: str, operation: str, commit: Callable[[], Any], *,
                prepare: Callable[[], Any] | None = None, cancel: threading.Event | None = None) -> dict:
        """Check, optional prepare, revalidate, commit; not cross-database atomic."""
        with self._lock:
            decision = self.authorize(access_token, operation, cancel=cancel)
            if not decision["isAuthorized"]:
                return decision
            if prepare:
                prepare()
            self._ready()
            decision = self.authorize(access_token, operation, cancel=cancel)
            if decision["isAuthorized"]:
                if cancel and cancel.is_set():
                    raise AegirIntegrationError("cancelled")
                commit()
            return decision

    def disconnect(self):
        with self._lock:
            self._ready()
            self._disconnect()

    def close(self):
        self._lifetime.set()
        self._api.close()
        self._web.close()
        with self._lock:
            if not self._disposed:
                self._disconnect()
                self._disposed = True

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

