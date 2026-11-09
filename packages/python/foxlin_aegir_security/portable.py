from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
import hashlib
import time


@dataclass(slots=True)
class TrustCoreAlgorithmDescriptor:
    algorithmId: str
    hybrid: bool


@dataclass(slots=True)
class TrustCoreSignatureEnvelope:
    keyId: str
    algorithm: TrustCoreAlgorithmDescriptor
    signatureBytes: bytes


@dataclass(slots=True)
class SafeEnvelopeRecord:
    envelopeId: str
    payloadType: str
    canonicalPayload: str
    payloadHash: str
    createdAtUtc: str
    signatureEnvelope: TrustCoreSignatureEnvelope | None


@dataclass(slots=True)
class SafeEnvelopeValidationResult:
    isValid: bool
    reason: str

    @property
    def isAuthenticated(self) -> bool:
        """Always false: this portable envelope is integrity-only."""
        return False


def compute_payload_digest(payload: bytes) -> str:
    """SHA-256 of exact bytes as lowercase hex. Integrity only; no authentication."""
    return hashlib.sha256(payload).hexdigest()


def sign_challenge_payload(payload: bytes) -> bytes:
    """Deprecated unsupported keyless authority; always raises NotImplementedError."""
    raise NotImplementedError("Keyless signing is unsupported. Use an authorized keyed signing contract.")


def verify_challenge_payload(payload: bytes, signature: bytes) -> bool:
    """Deprecated unsupported keyless authority; always rejects, including historical digests."""
    return False


def sign_proof_receipt_payload(payload: bytes) -> bytes:
    """Deprecated unsupported keyless authority; always raises NotImplementedError."""
    raise NotImplementedError("Keyless signing is unsupported. Use an authorized keyed signing contract.")


def verify_proof_receipt_payload(payload: bytes, signature: bytes) -> bool:
    """Deprecated unsupported keyless authority; always rejects, including historical digests."""
    return False


def sign_identity_token_payload(payload: bytes) -> bytes:
    """Deprecated unsupported keyless authority; always raises NotImplementedError."""
    raise NotImplementedError("Keyless signing is unsupported. Use an authorized keyed signing contract.")


def verify_identity_token_payload(payload: bytes, signature: bytes) -> bool:
    """Deprecated unsupported keyless authority; always rejects, including historical digests."""
    return False


def create_safe_envelope(
    payload_type: str,
    canonical_payload: str,
    signature_envelope: TrustCoreSignatureEnvelope | None = None,
) -> SafeEnvelopeRecord:
    if not payload_type.strip():
        raise ValueError("payload_type is required")

    if not canonical_payload.strip():
        raise ValueError("canonical_payload is required")

    return SafeEnvelopeRecord(
        envelopeId=_runtime_id("env"),
        payloadType=payload_type,
        canonicalPayload=canonical_payload,
        payloadHash=_payload_hash(canonical_payload),
        createdAtUtc=_utc_now(),
        signatureEnvelope=signature_envelope,
    )


def validate_safe_envelope(envelope: SafeEnvelopeRecord) -> SafeEnvelopeValidationResult:
    if envelope.payloadHash != _payload_hash(envelope.canonicalPayload):
        return SafeEnvelopeValidationResult(isValid=False, reason="payload_hash_mismatch")

    if envelope.signatureEnvelope is not None:
        return SafeEnvelopeValidationResult(isValid=False, reason="unsupported_signature")

    return SafeEnvelopeValidationResult(isValid=True, reason="integrity_only")


@dataclass(slots=True)
class AgentToAgentMessageRecord:
    messageId: str
    senderAgentId: str
    recipientAgentId: str
    messageType: str
    correlationId: str
    envelope: SafeEnvelopeRecord
    sentAtUtc: str
    receivedAtUtc: str | None


@dataclass(slots=True)
class AgentToAgentReceiveResult:
    accepted: bool
    reason: str
    message: AgentToAgentMessageRecord | None


class InMemoryAgentToAgentProtocol:
    """A local, in-process message queue for development and offline tests.

    .. deprecated::
        This is a simulation, not Aegir protection. Its envelopes are not encrypted, its
        signatures are not cryptographic, and nothing here is bound to an Aegir transaction or
        checked against an agent identity. For real agent-to-agent protection use
        :meth:`AegirSecurityClient.sendAgentMessage` and
        :meth:`AegirSecurityClient.receiveAgentMessage`, which go through the server's
        ML-KEM-768 / AES-256-GCM / ML-DSA-65 envelope.
    """

    def __init__(self) -> None:
        self._inbox: dict[str, list[AgentToAgentMessageRecord]] = {}

    def send(
        self,
        sender_agent_id: str,
        recipient_agent_id: str,
        message_type: str,
        canonical_payload: str,
        correlation_id: str | None = None,
        signature_envelope: TrustCoreSignatureEnvelope | None = None,
    ) -> AgentToAgentMessageRecord:
        if not sender_agent_id.strip():
            raise ValueError("sender_agent_id is required")
        if not recipient_agent_id.strip():
            raise ValueError("recipient_agent_id is required")
        if not message_type.strip():
            raise ValueError("message_type is required")

        message = AgentToAgentMessageRecord(
            messageId=_runtime_id("msg"),
            senderAgentId=sender_agent_id,
            recipientAgentId=recipient_agent_id,
            messageType=message_type,
            correlationId=correlation_id.strip() if correlation_id and correlation_id.strip() else _runtime_id("corr"),
            envelope=create_safe_envelope(f"agent:{message_type}", canonical_payload, signature_envelope),
            sentAtUtc=_utc_now(),
            receivedAtUtc=None,
        )
        self._inbox.setdefault(recipient_agent_id, []).append(message)
        self._inbox[recipient_agent_id].sort(key=lambda item: item.sentAtUtc)
        return message

    def get_inbox(self, recipient_agent_id: str) -> list[AgentToAgentMessageRecord]:
        return list(self._inbox.get(recipient_agent_id, []))

    def receive(self, recipient_agent_id: str, message_id: str) -> AgentToAgentReceiveResult:
        for index, message in enumerate(self._inbox.get(recipient_agent_id, [])):
            if message.messageId != message_id:
                continue

            validation = validate_safe_envelope(message.envelope)
            if not validation.isValid:
                return AgentToAgentReceiveResult(accepted=False, reason=validation.reason, message=message)

            accepted = AgentToAgentMessageRecord(
                messageId=message.messageId,
                senderAgentId=message.senderAgentId,
                recipientAgentId=message.recipientAgentId,
                messageType=message.messageType,
                correlationId=message.correlationId,
                envelope=message.envelope,
                sentAtUtc=message.sentAtUtc,
                receivedAtUtc=_utc_now(),
            )
            self._inbox[recipient_agent_id][index] = accepted
            return AgentToAgentReceiveResult(accepted=True, reason="accepted", message=accepted)

        return AgentToAgentReceiveResult(accepted=False, reason="message_not_found", message=None)


@dataclass(slots=True)
class BudgetEnvelope:
    controlType: str
    subjectKey: str
    windowStartedAtUtc: str
    windowEndsAtUtc: str
    limit: int
    consumed: int
    remaining: int
    isExhausted: bool


@dataclass(frozen=True, slots=True)
class BudgetEnvelopeOptions:
    identityScanLimit: int = 25
    externalLookupLimit: int = 50
    connectionGraphRebuildLimit: int = 10
    windowMs: int = 60_000


class BudgetExhaustedError(Exception):
    def __init__(self, envelope: BudgetEnvelope):
        super().__init__(f"Budget exhausted for {envelope.controlType} on '{envelope.subjectKey}'.")
        self.envelope = envelope


class InMemoryBudgetEnvelopeService:
    def __init__(
        self,
        options: BudgetEnvelopeOptions | None = None,
        *,
        identity_scan_limit: int | None = None,
        external_lookup_limit: int | None = None,
        connection_graph_rebuild_limit: int | None = None,
        window_seconds: int | None = None,
    ) -> None:
        resolved = options or BudgetEnvelopeOptions()
        self._limits = {
            "IdentityScan": identity_scan_limit if identity_scan_limit is not None else resolved.identityScanLimit,
            "ExternalLookup": external_lookup_limit if external_lookup_limit is not None else resolved.externalLookupLimit,
            "ConnectionGraphRebuild": connection_graph_rebuild_limit
            if connection_graph_rebuild_limit is not None
            else resolved.connectionGraphRebuildLimit,
        }
        self._window_seconds = window_seconds if window_seconds is not None else resolved.windowMs / 1000
        self._counters: dict[str, tuple[datetime, int]] = {}

    def get_envelope(self, control_type: str, subject_key: str) -> BudgetEnvelope:
        key = _budget_key(control_type, subject_key)
        current = self._counters.get(key, (datetime.now(UTC), 0))
        return _to_budget_envelope(control_type, subject_key, current[0], current[1], self._window_seconds, self._limits[control_type])

    def consume(self, control_type: str, subject_key: str) -> BudgetEnvelope:
        key = _budget_key(control_type, subject_key)
        now = datetime.now(UTC)
        started_at, consumed = self._counters.get(key, (now, 0))
        if now - started_at >= timedelta(seconds=self._window_seconds):
            started_at, consumed = now, 0
        consumed += 1
        self._counters[key] = (started_at, consumed)

        envelope = _to_budget_envelope(control_type, subject_key, started_at, consumed, self._window_seconds, self._limits[control_type])
        if consumed > envelope.limit:
            raise BudgetExhaustedError(envelope)
        return envelope


def _payload_hash(canonical_payload: str) -> str:
    return hashlib.sha256(canonical_payload.encode("utf-8")).hexdigest()


def _runtime_id(prefix: str) -> str:
    return f"{prefix}_{time.time_ns()}"


def _utc_now() -> str:
    return datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _budget_key(control_type: str, subject_key: str) -> str:
    if not subject_key.strip():
        raise ValueError("subject_key is required")
    return f"{control_type}:{subject_key.strip()}"


def _to_budget_envelope(
    control_type: str,
    subject_key: str,
    window_started_at: datetime,
    consumed: int,
    window_seconds: int,
    limit: int,
) -> BudgetEnvelope:
    return BudgetEnvelope(
        controlType=control_type,
        subjectKey=subject_key.strip(),
        windowStartedAtUtc=window_started_at.replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        windowEndsAtUtc=(window_started_at + timedelta(seconds=window_seconds)).replace(microsecond=0).isoformat().replace("+00:00", "Z"),
        limit=limit,
        consumed=consumed,
        remaining=max(limit - consumed, 0),
        isExhausted=consumed >= limit,
    )
