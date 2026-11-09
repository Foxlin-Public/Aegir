"""Foxlin Industries. Native adversarial tests; real server parity is a separate suite."""
import json
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch
from foxlin_aegir_security import AegirIntegrationClient, AegirIntegrationError, SqliteAuthorizationJournal
from foxlin_aegir_security.integration import _json, _HttpsTransport

def event(identifier, version=1, kind="granted", transaction="shared-transaction"):
    return dict(protocolVersion=1, transactionId=transaction, eventId=identifier, groupId="application-group",
                userId="application-subject", eventType=kind, groupVersion=version)

def snapshot(version):
    return dict(snapshotId="snapshot", groups=[dict(groupId="application-group", groupVersion=version, subjects=[])])

def permit():
    return dict(isAuthorized=True, reason="authorized", applicationSubjectId="application-subject",
                authorizationEpoch=0, effectiveGroupIds=["application-group"], permissions=["read", "write"])

class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="aegir-integration-native-")
        self.journal = SqliteAuthorizationJournal(Path(self.directory.name) / "journal.db", "synthetic-stream")
        self.client = None

    def tearDown(self):
        if self.client:
            self.client.close()
        self.journal.close()
        self.directory.cleanup()

    def client_fixture(self, **extra):
        self.client = AegirIntegrationClient(api_base_url="https://example.invalid/apis/", web_base_url="https://example.invalid/",
            application_credential="synthetic", organization_id="synthetic-org", application_id="synthetic-app",
            journal=self.journal, timeout_seconds=.1, **extra)
        return self.client

    def test_duplicate_receipt_restart(self):
        self.assertEqual(self.journal.apply([event("one")])["newEffects"], 1)
        self.journal.set_connected(True)
        self.journal.close()
        self.journal = SqliteAuthorizationJournal(Path(self.directory.name) / "journal.db", "synthetic-stream")
        self.assertFalse(self.journal.inspect()["connected"])
        self.assertEqual(self.journal.apply([event("one")])["newEffects"], 0)
        self.assertEqual(self.journal.inspect()["effects"], 1)

    def test_same_transaction_distinct_events(self):
        self.assertEqual(self.journal.apply([event("one"), event("two")])["newEffects"], 2)

    def test_late_grant(self):
        self.journal.apply([event("one"), event("two", 2, "revoked")])
        self.assertEqual(self.journal.apply([event("late", 1)])["newEffects"], 0)
        self.assertEqual(self.journal.inspect()["versions"]["application-group"], 2)

    def test_gap_atomic_rollback(self):
        self.assertTrue(self.journal.apply([event("one"), event("gap", 4)])["requiresSnapshot"])
        self.assertEqual(self.journal.inspect()["receipts"], 0)

    def test_unknown_type_atomic_rollback(self):
        self.assertTrue(self.journal.apply([event("one"), event("future", 2, "futureGrant")])["requiresSnapshot"])
        self.assertEqual(self.journal.inspect()["effects"], 0)

    def test_unsupported_protocol(self):
        value = event("one")
        value["protocolVersion"] = 2
        with self.assertRaisesRegex(AegirIntegrationError, "unsupported_event_protocol"):
            self.journal.apply([value])

    def test_boolean_protocol_rejected(self):
        value = event("one")
        value["protocolVersion"] = True
        with self.assertRaisesRegex(AegirIntegrationError, "unsupported_event_protocol"):
            self.journal.apply([value])

    def test_absent_group_preserves_highwater(self):
        self.journal.apply_snapshot(snapshot(5))
        self.journal.apply_snapshot(dict(snapshotId="empty", groups=[]))
        with self.assertRaisesRegex(AegirIntegrationError, "snapshot_rollback"):
            self.journal.apply_snapshot(snapshot(4))

    def test_deep_json_bounded(self):
        with self.assertRaisesRegex(AegirIntegrationError, "invalid_server_response"):
            _json("[" * 40 + "0" + "]" * 40)

    def test_expired_or_subjectless_authentication(self):
        client = self.client_fixture()
        for extra in ({"subjectId": ""}, {"expiresAtUtc": "2000-01-01T00:00:00Z"}):
            value = dict(accessToken="private-ticket", subjectId="synthetic", organizationId="synthetic-org",
                         applicationId="synthetic-app", expiresAtUtc="2999-01-01T00:00:00Z", authorizationEpoch=0)
            value.update(extra)
            client._web.request = lambda *a, **k: (200, value)
            with self.assertRaisesRegex(AegirIntegrationError, "invalid_server_response"):
                client.authenticate("synthetic", "synthetic-password")

    def test_privacy_field_rejected(self):
        value = event("one")
        value["email"] = "synthetic@example.invalid"
        with self.assertRaisesRegex(AegirIntegrationError, "unsupported_event_protocol"):
            self.journal.apply([value])

    def test_identity_conflict_transaction_rollback(self):
        self.journal.apply([event("one")])
        with self.assertRaisesRegex(AegirIntegrationError, "event_identity_conflict"):
            self.journal.apply([event("two", 2), event("one", 1, "revoked")])
        self.assertEqual(self.journal.inspect()["effects"], 1)

    def test_snapshot_rollback(self):
        self.journal.apply_snapshot(snapshot(5))
        with self.assertRaisesRegex(AegirIntegrationError, "snapshot_rollback"):
            self.journal.apply_snapshot(snapshot(4))

    def test_binding_mismatch(self):
        with self.assertRaisesRegex(AegirIntegrationError, "journal_binding_mismatch"):
            SqliteAuthorizationJournal(Path(self.directory.name) / "journal.db", "other")

    def test_invalid_url(self):
        for url in ("http://example.invalid/", "https://user:secret@example.invalid/", "https://example.invalid/?q=x",
                    "https://example.invalid/#f", "https://example.invalid/no-slash", "https://example.invalid/%2e/"):
            with self.assertRaisesRegex(AegirIntegrationError, "invalid_configuration"):
                AegirIntegrationClient(api_base_url=url, web_base_url="https://example.invalid/", application_credential="x",
                    organization_id="org", application_id="app", journal=self.journal)

    def test_pin_nonloopback_rejected(self):
        with self.assertRaisesRegex(AegirIntegrationError, "invalid_configuration"):
            self.client_fixture(certificate_sha256="a" * 64)

    def test_startup_fail_closed(self):
        client = self.client_fixture()
        self.assertFalse(client.authorize("ticket", "read")["isAuthorized"])
        self.assertEqual(client.authorize("ticket", "delete")["reason"], "unsupported_operation")

    def test_contradictory_permit(self):
        client = self.client_fixture()
        for status, changes in ((403, {}), (200, {"reason": "license_required"}),
                                (200, {"permissions": ["read"]}), (200, {"applicationSubjectId": None})):
            client._connected = True
            value = dict(permit(), **changes)
            client._api.request = lambda *a, **k: (status, value)
            count = []
            self.assertFalse(client.execute("ticket", "write", lambda: count.append(1))["isAuthorized"])
            self.assertEqual(count, [])

    def test_revalidation(self):
        client = self.client_fixture()
        client._connected = True
        results = [(200, permit()), (403, dict(permit(), isAuthorized=False, reason="license_required"))]
        client._api.request = lambda *a, **k: results.pop(0)
        count = []
        self.assertFalse(client.execute("ticket", "write", lambda: count.append(1), prepare=lambda: None)["isAuthorized"])
        self.assertEqual(count, [])
        self.assertEqual(results, [])

    def test_healthy_poll_does_not_disconnect(self):
        client = self.client_fixture()
        client._connected = True
        self.journal.set_connected(True)
        client._api.request = lambda *a, **k: (200, dict(deliveryId=None, events=[], requiresSnapshot=False, reason=None, retryAfterSeconds=1))
        self.assertTrue(client.poll()["connected"])
        self.assertTrue(self.journal.inspect()["connected"])

    def test_cancelled_never_commits(self):
        client = self.client_fixture()
        client._connected = True
        cancel = threading.Event()
        cancel.set()
        count = []
        with self.assertRaisesRegex(AegirIntegrationError, "cancelled"):
            client.execute("ticket", "write", lambda: count.append(1), cancel=cancel)
        self.assertEqual(count, [])

    def test_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(AegirIntegrationError, "invalid_server_response"):
            _json('{"isAuthorized":false,"isAuthorized":true}')
        with self.assertRaisesRegex(AegirIntegrationError, "invalid_server_response"):
            _json('{"epoch":NaN}')

    def test_disposal_during_prepare(self):
        client = self.client_fixture()
        client._connected = True
        client._api.request = lambda *a, **k: (200, permit())
        count = []
        with self.assertRaisesRegex(AegirIntegrationError, "disposed"):
            client.execute("ticket", "write", lambda: count.append(1), prepare=client.close)
        self.assertEqual(count, [])

    def test_optional_outer_extensions(self):
        client = self.client_fixture()
        client._connected = True
        client._api.request = lambda *a, **k: (200, dict(permit(), futureOptional="ignored"))
        count = []
        self.assertTrue(client.execute("ticket", "write", lambda: count.append(1))["isAuthorized"])
        self.assertEqual(count, [1])
        client._web.request = lambda *a, **k: (200, dict(accessToken="private-ticket", subjectId="synthetic",
            organizationId="synthetic-org", applicationId="synthetic-app", expiresAtUtc="2999-01-01T00:00:00Z",
            authorizationEpoch=0, futureOptional="ignored"))
        self.assertEqual(client.authenticate("synthetic", "synthetic-password")["organizationId"], "synthetic-org")

    def test_transport_close_captures_socket_once(self):
        class SyntheticSocket:
            closed = False
            def shutdown(self, _):
                self.closed = True
        class SyntheticConnection:
            reads = 0
            closed = False
            socket = SyntheticSocket()
            @property
            def sock(self):
                self.reads += 1
                return self.socket if self.reads == 1 else None
            def close(self):
                self.closed = True
        transport = _HttpsTransport("https://example.invalid/", None, 1)
        connection = SyntheticConnection()
        transport._active.add(connection)
        transport.close()
        self.assertEqual(connection.reads, 1)
        self.assertTrue(connection.socket.closed)
        self.assertTrue(connection.closed)

    def test_owned_transport_rejects_misleading_media_types(self):
        class SyntheticResponse:
            status = 200
            media_type = "application/jsonp"
            def read(self, _):
                return json.dumps(dict(accessToken="private-ticket", subjectId="synthetic", organizationId="synthetic-org",
                    applicationId="synthetic-app", expiresAtUtc="2999-01-01T00:00:00Z", authorizationEpoch=0)).encode()
            def getheader(self, name, default=""):
                return self.media_type if name == "Content-Type" else default
        class SyntheticConnection:
            response = SyntheticResponse()
            sock = None
            def connect(self): pass
            def request(self, *args, **kwargs): pass
            def getresponse(self): return self.response
            def close(self): pass
        connection = SyntheticConnection()
        client = self.client_fixture()
        with patch("http.client.HTTPSConnection", return_value=connection):
            for media_type in ("application/jsonp", "text/plain; note=application/json"):
                connection.response.media_type = media_type
                with self.assertRaisesRegex(AegirIntegrationError, "invalid_server_response"):
                    client.authenticate("synthetic", "synthetic-password")
            connection.response.media_type = "Application/JSON; charset=utf-8"
            self.assertEqual(client.authenticate("synthetic", "synthetic-password")["applicationId"], "synthetic-app")

if __name__ == "__main__":
    unittest.main()

