"""Foxlin Industries. Local JSON-lines integration example; no secrets in output."""
import hashlib
import json
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from foxlin_aegir_security import AegirIntegrationClient, AegirIntegrationError, AegirMfaRequired, SqliteAuthorizationJournal

client = journal = None
ticket = None
try:
    config = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8-sig"))
    binding = hashlib.sha256(json.dumps([config["apiBaseUrl"], config["organizationId"], config["applicationId"]], separators=(",", ":")).encode()).hexdigest()
    journal = SqliteAuthorizationJournal(config["journalPath"], binding)
    client = AegirIntegrationClient(api_base_url=config["apiBaseUrl"], web_base_url=config["webBaseUrl"],
        organization_id=config["organizationId"], application_id=config["applicationId"],
        application_credential=config["applicationCredential"], journal=journal,
        certificate_sha256=config.get("certificateSha256"), timeout_seconds=config.get("timeoutMs", 15000) / 1000)
    for line in sys.stdin:
        command = None
        try:
            command = json.loads(line)
            op = command["op"]
            if op == "authenticate":
                ticket = None
                try:
                    session = client.authenticate(config["username"], config["password"], challenge_id=command.get("challengeId"), totp_code=command.get("totpCode"))
                    ticket = session["accessToken"]
                    result = {"authenticated": True}
                except AegirMfaRequired as challenge:
                    ticket = None
                    result = {"authenticated": False, "mfaRequired": True, "challengeId": challenge.challenge_id}
            elif op == "reconnect":
                result = client.reconnect()
            elif op == "poll":
                result = client.poll(acknowledge=command.get("acknowledge", True))
            elif op == "check":
                result = client.authorize(ticket or "", command.get("operation"))
            elif op == "execute":
                count = [0]
                def commit():
                    count[0] += 1
                result = dict(client.execute(ticket or "", command.get("operation"), commit), effects=count[0])
            elif op == "disconnect":
                client.disconnect()
                result = {"connected": False}
            elif op == "state":
                result = journal.inspect()
            elif op == "close":
                client.close()
                journal.close()
                result = {"closed": True}
            else:
                raise AegirIntegrationError("unknown_command")
            print(json.dumps(dict(requestId=command.get("requestId"), ok=True, **result)), flush=True)
            if op == "close":
                break
        except Exception as error:
            print(json.dumps({"requestId": command.get("requestId") if isinstance(command, dict) else None,
                              "ok": False, "error": error.code if isinstance(error, AegirIntegrationError) else "integration_failure"}), flush=True)
except Exception as error:
    print(json.dumps({"requestId": None, "ok": False, "error": error.code if isinstance(error, AegirIntegrationError) else "configuration_failure"}), flush=True)
    raise SystemExit(1)
finally:
    if client:
        client.close()
    if journal:
        journal.close()
    ticket = None

