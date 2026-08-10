"""End-to-end flow against a running Aegir API host.

This is NOT part of the unit suite. It talks to a real host and a real database, which the
unit tests must never do. Run it against a development deployment::

    AEGIR_BASE_URL=http://127.0.0.1:5199/apis \\
    AEGIR_DEVELOPER_KEY=devkey_x:secret \\
    python tests/live_flow.py

It exercises the capabilities Beta-1 claims, in the order a real integrator would: register
agents, open a transaction, protect a message from one agent to another, prove the wrong agent
cannot open it, prove it cannot be moved to another transaction, and pull the signed receipt.
"""

from __future__ import annotations

import base64
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from foxlin_aegir_security import AegirSecurityClient, AegirSecurityError  # noqa: E402

BASE_URL = os.environ.get("AEGIR_BASE_URL")
DEVELOPER_KEY = os.environ.get("AEGIR_DEVELOPER_KEY")

if not BASE_URL or not DEVELOPER_KEY:
    print("Set AEGIR_BASE_URL and AEGIR_DEVELOPER_KEY to run the live flow.")
    sys.exit(2)


def step(name: str) -> None:
    print(f"\n== {name}")


def assert_refused(run, expected_status: int, failure_message: str) -> None:
    """Assert that an operation is refused, and with the status the contract promises."""
    try:
        run()
    except AegirSecurityError as error:
        assert error.status == expected_status, f"expected {expected_status}, got {error.status}"
        print(f"   refused with {error.status} {error.code}")
        return

    raise AssertionError(failure_message)


suffix = int(time.time() * 1000)
developer = AegirSecurityClient(base_url=BASE_URL, developer_key=DEVELOPER_KEY)

step("developer token")
token = developer.getToken()
assert token["token_type"] == "Bearer"
print(f"   scopes: {' '.join(token['scopes'])}")

step("register three agents")
alpha = developer.registerAgent(f"py-alpha-{suffix}", scopes=["agent:message", "transaction:write"])
beta = developer.registerAgent(f"py-beta-{suffix}", scopes=["agent:message", "transaction:write"])
gamma = developer.registerAgent(f"py-gamma-{suffix}", scopes=["agent:message", "transaction:write"])
print(f"   alpha={alpha['agent']['agentId']} beta={beta['agent']['agentId']}")

# Each agent authenticates as itself. The developer key is not reused below this point.
alpha_client = AegirSecurityClient(base_url=BASE_URL)
alpha_client.useAgentKey(alpha["agentKey"])

beta_client = AegirSecurityClient(base_url=BASE_URL)
beta_client.useAgentKey(beta["agentKey"])

gamma_client = AegirSecurityClient(base_url=BASE_URL)
gamma_client.useAgentKey(gamma["agentKey"])

step("open a transaction before the protected operation")
transaction = alpha_client.createTransaction("agent.message.send")
assert transaction["transactionId"].startswith("AGTX-")
assert transaction["status"] == "Created"
assert transaction["agentPrincipalId"] == alpha["agent"]["agentId"]
print(f"   {transaction['transactionId']}")

step("protect a payload from alpha to beta")
secret = json.dumps({"finding": "CVE-2026-0001", "severity": "high"})
message = alpha_client.sendAgentMessage(
    transaction["transactionId"],
    beta["agent"]["agentId"],
    "agent.finding.share",
    base64.b64encode(secret.encode("utf-8")).decode("ascii"),
)

header = message["envelope"]["header"]
assert header["kemAlgorithm"] == "ML-KEM-768"
assert header["signatureAlgorithm"] == "ML-DSA-65"
assert header["aeadAlgorithm"] == "AES-256-GCM"
assert header["transactionId"] == transaction["transactionId"]

# The payload must not be recoverable from the wire form.
assert "CVE-2026-0001" not in json.dumps(message)
print(f"   {header['version']} envelope, ciphertext {len(message['envelope']['ciphertext'])} b64 chars")

step("the wrong agent cannot open it")
assert_refused(
    lambda: gamma_client.receiveAgentMessage(message),
    403,
    "gamma opened a message addressed to beta",
)

step("it cannot be moved to another transaction")
other = alpha_client.createTransaction("agent.message.send")
moved = {
    "transactionId": other["transactionId"],
    "envelope": {
        **message["envelope"],
        "header": {**header, "transactionId": other["transactionId"]},
    },
}
assert_refused(
    lambda: beta_client.receiveAgentMessage(moved),
    403,
    "an envelope minted for one transaction was accepted under another",
)

step("the addressee opens it")
delivery = beta_client.receiveAgentMessage(message)
assert delivery["senderAgentId"] == alpha["agent"]["agentId"]
assert delivery["action"] == "agent.finding.share"
assert base64.b64decode(delivery["payload"]).decode("utf-8") == secret
print(f"   delivered from {delivery['senderAgentId']}")

step("replaying it fails")
assert_refused(
    lambda: beta_client.receiveAgentMessage(message),
    403,
    "a protected message was accepted twice",
)

step("the transaction trail and signed receipt")
events = developer.getTransactionEvents(transaction["transactionId"])
print("   " + " -> ".join(entry["eventType"] for entry in events))
assert [entry["eventType"] for entry in events] == [
    "transaction.created",
    "transaction.authorized",
    "transaction.in_progress",
    "transaction.completed",
]

# No event may carry the payload. Aegir proves the exchange, it does not retain it.
for entry in events:
    assert "CVE-2026-0001" not in (entry.get("detail") or "")

receipt = developer.getTransactionReceipt(transaction["transactionId"])
assert receipt["algorithm"] == "ML-DSA-65"
assert receipt["transactionId"] == transaction["transactionId"]
assert "CVE-2026-0001" not in json.dumps(receipt)

verification = developer.verifyTransactionReceipt(receipt)
assert verification["valid"] is True, f"receipt did not verify: {verification['status']}"
print(f"   receipt {receipt['signingKid']} verified: {verification['status']}")

step("a tampered receipt does not verify")
tampered = {**receipt, "declaredAction": "agent.credential.export"}
tampered_result = developer.verifyTransactionReceipt(tampered)
assert tampered_result["valid"] is False
print(f"   tampered receipt rejected: {tampered_result['status']}")

step("audit authority does not confer identity resolution or decryption")
narrow = AegirSecurityClient(base_url=BASE_URL, developer_key=DEVELOPER_KEY)
narrow.useNarrowedToken("transaction:read")
narrow.getTransaction(transaction["transactionId"])
assert_refused(
    lambda: narrow.registerAgent("should-not-be-possible"),
    403,
    "a transaction:read token was able to administer agents",
)

print("\nlive flow ok")
