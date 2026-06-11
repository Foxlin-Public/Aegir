from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any


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
            exposureScore=float(payload["exposureScore"]),
            trustScore=float(payload["trustScore"]),
            connectionClarityScore=float(payload["connectionClarityScore"]),
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
            nodeType=IdentityGraphNodeType(payload["nodeType"]),
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
            edgeType=IdentityGraphEdgeType(payload["edgeType"]),
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
            category=ExposureFindingCategory(payload["category"]),
            severity=ExposureFindingSeverity(payload["severity"]),
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
            exposureScore=float(payload["exposureScore"]),
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
            actionType=IdentityActionType(payload["actionType"]),
            status=IdentityActionStatus(payload["status"]),
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
