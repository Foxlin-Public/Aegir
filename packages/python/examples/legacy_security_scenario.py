"""Foxlin Industries. Approved synthetic local host only; private config, no secret output."""
import json
from pathlib import Path
import sys
from foxlin_aegir_security import AegirSecurityClient, PerformIdentityActionRequest

operation = "configuration"
client = None


def run(op, action):
    global operation
    operation = op
    value = action()
    print(json.dumps({"op": operation, "ok": True}), flush=True)
    return value


try:
    raw = Path(sys.argv[1]).read_bytes()
    if len(raw) > 65536:
        raise ValueError()
    config = json.loads(raw.decode("utf-8", errors="strict"))
    subject = config["subjectId"]
    if not isinstance(subject, str) or not subject.strip():
        raise ValueError()
    client = AegirSecurityClient(base_url=config["apiBaseUrl"], developer_key=config["developerKey"],
        expected_subject_id=subject, certificate_sha256=config.get("certificateSha256"),
        timeout_seconds=config.get("timeoutMs", 10000) / 1000)
    run("scan", lambda: client.scanIdentity(subject))
    run("graph", lambda: client.getIdentityGraph(subject))
    run("graphJson", lambda: client.getIdentityGraphJson(subject))
    run("exposure", lambda: client.getExposureSummary(subject))
    action = run("action", lambda: client.performAction(PerformIdentityActionRequest(subject,
        "RequestClarity", reason="Synthetic local SDK contract exercise")))
    run("reverse", lambda: client.reverseAction(action.actionId, "Synthetic local SDK contract exercise"))
    run("history", lambda: client.getActionHistory(subject))
except Exception:
    print(json.dumps({"op": operation, "ok": False}), flush=True)
    sys.exit(1)
finally:
    if client is not None:
        client.close()
