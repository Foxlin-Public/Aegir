from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any
import math


JsonMap = dict[str, Any]


class IdentityActionType(StrEnum):
    LockIdentity = "LockIdentity"
    DisconnectService = "DisconnectService"
    VerifyConnection = "VerifyConnection"
    RequestClarity = "RequestClarity"


class IdentityActionStatus(StrEnum):
    Completed = "Completed"
    Reversed = "Reversed"


class IdentityGraphNodeType(StrEnum):
    Platform = "Platform"
    Developer = "Developer"
    DeveloperKey = "DeveloperKey"
    Application = "Application"
    Environment = "Environment"
    User = "User"
    Device = "Device"
    Credential = "Credential"
    Challenge = "Challenge"
    Token = "Token"
    AuditAnchor = "AuditAnchor"
    PolicyScope = "PolicyScope"
    ExternalService = "ExternalService"


class IdentityGraphEdgeType(StrEnum):
    Owns = "Owns"
    Issued = "Issued"
    Registered = "Registered"
    BelongsTo = "BelongsTo"
    AuthorizedFor = "AuthorizedFor"
    ScopedTo = "ScopedTo"
    Uses = "Uses"
    PresentedBy = "PresentedBy"
    DerivedFrom = "DerivedFrom"
    ApprovedBy = "ApprovedBy"
    RevokedBy = "RevokedBy"
    AnchoredBy = "AnchoredBy"
    ConnectedTo = "ConnectedTo"
    ObservedOn = "ObservedOn"


class ExposureFindingCategory(StrEnum):
    WeakConnection = "WeakConnection"
    UnknownConnection = "UnknownConnection"
    StaleCredential = "StaleCredential"
    HighRiskLinkage = "HighRiskLinkage"


class ExposureFindingSeverity(StrEnum):
    Low = "Low"
    Medium = "Medium"
    High = "High"


@dataclass(slots=True)
class IdentityGraphScores:
    exposureScore: float
    trustScore: float
    connectionClarityScore: float

    @staticmethod
    def from_json(payload: JsonMap) -> "IdentityGraphScores":
        return IdentityGraphScores(
            exposureScore=_wire_number(payload["exposureScore"]),
            trustScore=_wire_number(payload["trustScore"]),
            connectionClarityScore=_wire_number(payload["connectionClarityScore"]),
        )


@dataclass(slots=True)
class IdentityGraphNode:
    nodeId: str
    nodeType: IdentityGraphNodeType
    displayName: str
    status: str
    trustTier: str
    observedAtUtc: str
    lastVerifiedAtUtc: str | None
    metadata: JsonMap

    @staticmethod
    def from_json(payload: JsonMap) -> "IdentityGraphNode":
        return IdentityGraphNode(
            nodeId=payload["nodeId"],
            nodeType=_wire_enum(IdentityGraphNodeType, payload["nodeType"]),
            displayName=payload["displayName"],
            status=payload["status"],
            trustTier=payload["trustTier"],
            observedAtUtc=payload["observedAtUtc"],
            lastVerifiedAtUtc=payload.get("lastVerifiedAtUtc"),
            metadata=dict(payload.get("metadata", {})),
        )


@dataclass(slots=True)
class IdentityGraphEdge:
    edgeId: str
    edgeType: IdentityGraphEdgeType
    fromNodeId: str
    toNodeId: str
    status: str
    trustWeight: float
    evidenceType: str
    reason: str
    observedAtUtc: str
    lastVerifiedAtUtc: str | None
    metadata: JsonMap

    @staticmethod
    def from_json(payload: JsonMap) -> "IdentityGraphEdge":
        return IdentityGraphEdge(
            edgeId=payload["edgeId"],
            edgeType=_wire_enum(IdentityGraphEdgeType, payload["edgeType"]),
            fromNodeId=payload["fromNodeId"],
            toNodeId=payload["toNodeId"],
            status=payload["status"],
            trustWeight=float(payload["trustWeight"]),
            evidenceType=payload["evidenceType"],
            reason=payload["reason"],
            observedAtUtc=payload["observedAtUtc"],
            lastVerifiedAtUtc=payload.get("lastVerifiedAtUtc"),
            metadata=dict(payload.get("metadata", {})),
        )


@dataclass(slots=True)
class IdentityGraphSnapshot:
    graphId: str
    generatedAtUtc: str
    scores: IdentityGraphScores
    nodes: list[IdentityGraphNode]
    edges: list[IdentityGraphEdge]
    metadata: JsonMap

    @staticmethod
    def from_json(payload: JsonMap) -> "IdentityGraphSnapshot":
        return IdentityGraphSnapshot(
            graphId=payload["graphId"],
            generatedAtUtc=payload["generatedAtUtc"],
            scores=IdentityGraphScores.from_json(payload["scores"]),
            nodes=[IdentityGraphNode.from_json(item) for item in payload.get("nodes", [])],
            edges=[IdentityGraphEdge.from_json(item) for item in payload.get("edges", [])],
            metadata=dict(payload.get("metadata", {})),
        )


@dataclass(slots=True)
class ExposureFinding:
    findingId: str
    category: ExposureFindingCategory
    severity: ExposureFindingSeverity
    summary: str
    nodeId: str | None
    edgeId: str | None
    metadata: JsonMap

    @staticmethod
    def from_json(payload: JsonMap) -> "ExposureFinding":
        return ExposureFinding(
            findingId=payload["findingId"],
            category=_wire_enum(ExposureFindingCategory, payload["category"]),
            severity=_wire_enum(ExposureFindingSeverity, payload["severity"]),
            summary=payload["summary"],
            nodeId=payload.get("nodeId"),
            edgeId=payload.get("edgeId"),
            metadata=dict(payload.get("metadata", {})),
        )


@dataclass(slots=True)
class ExposureSummary:
    graphId: str
    generatedAtUtc: str
    exposureScore: float
    findings: list[ExposureFinding]
    summaryText: str

    @staticmethod
    def from_json(payload: JsonMap) -> "ExposureSummary":
        return ExposureSummary(
            graphId=payload["graphId"],
            generatedAtUtc=payload["generatedAtUtc"],
            exposureScore=_wire_number(payload["exposureScore"]),
            findings=[ExposureFinding.from_json(item) for item in payload.get("findings", [])],
            summaryText=payload["summaryText"],
        )


@dataclass(slots=True)
class PerformIdentityActionRequest:
    subjectId: str
    actionType: IdentityActionType | str
    targetNodeId: str | None = None
    reason: str | None = None

    def to_json(self) -> JsonMap:
        payload: JsonMap = {
            "subjectId": self.subjectId,
            "actionType": self.actionType,
        }
        if self.targetNodeId is not None:
            payload["targetNodeId"] = self.targetNodeId
        if self.reason is not None:
            payload["reason"] = self.reason
        return payload


@dataclass(slots=True)
class IdentityActionRecord:
    actionId: str
    subjectId: str
    actionType: IdentityActionType
    status: IdentityActionStatus
    targetNodeId: str | None
    reason: str | None
    requestedAtUtc: str
    reversedAtUtc: str | None
    reverseReason: str | None
    metadata: JsonMap

    @staticmethod
    def from_json(payload: JsonMap) -> "IdentityActionRecord":
        return IdentityActionRecord(
            actionId=payload["actionId"],
            subjectId=payload["subjectId"],
            actionType=_wire_enum(IdentityActionType, payload["actionType"]),
            status=_wire_enum(IdentityActionStatus, payload["status"]),
            targetNodeId=payload.get("targetNodeId"),
            reason=payload.get("reason"),
            requestedAtUtc=payload["requestedAtUtc"],
            reversedAtUtc=payload.get("reversedAtUtc"),
            reverseReason=payload.get("reverseReason"),
            metadata=dict(payload.get("metadata", {})),
        )


@dataclass(slots=True)
class ScanIdentityResult:
    subjectId: str
    graph: IdentityGraphSnapshot
    exposure: ExposureSummary
    actionHistory: list[IdentityActionRecord]

    @staticmethod
    def from_json(payload: JsonMap) -> "ScanIdentityResult":
        return ScanIdentityResult(
            subjectId=payload["subjectId"],
            graph=IdentityGraphSnapshot.from_json(payload["graph"]),
            exposure=ExposureSummary.from_json(payload["exposure"]),
            actionHistory=[IdentityActionRecord.from_json(item) for item in payload.get("actionHistory", [])],
        )


def _wire_enum(enum_type,value):
    """Accept exact canonical C# numeric enums and retained public named values."""
    if type(value) is int:
        members=list(enum_type)
        if 1<=value<=len(members):return members[value-1]
        raise ValueError("Unknown enum value.")
    if not isinstance(value,str):raise ValueError("Invalid enum value.")
    try: return enum_type(value)
    except ValueError: raise ValueError("Unknown enum value.") from None


def _wire_number(value):
    if type(value) not in (int,float) or not math.isfinite(value):
        raise ValueError("Invalid numeric field.")
    return float(value)
