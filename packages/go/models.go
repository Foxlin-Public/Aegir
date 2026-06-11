package aegirsecurity

type IdentityActionType string

const (
	IdentityActionTypeLockIdentity      IdentityActionType = "LockIdentity"
	IdentityActionTypeDisconnectService IdentityActionType = "DisconnectService"
	IdentityActionTypeVerifyConnection  IdentityActionType = "VerifyConnection"
	IdentityActionTypeRequestClarity    IdentityActionType = "RequestClarity"
)

type IdentityActionStatus string

const (
	IdentityActionStatusCompleted IdentityActionStatus = "Completed"
	IdentityActionStatusReversed  IdentityActionStatus = "Reversed"
)

type IdentityGraphNodeType string

const (
	IdentityGraphNodeTypePlatform        IdentityGraphNodeType = "Platform"
	IdentityGraphNodeTypeDeveloper       IdentityGraphNodeType = "Developer"
	IdentityGraphNodeTypeDeveloperKey    IdentityGraphNodeType = "DeveloperKey"
	IdentityGraphNodeTypeApplication     IdentityGraphNodeType = "Application"
	IdentityGraphNodeTypeEnvironment     IdentityGraphNodeType = "Environment"
	IdentityGraphNodeTypeUser            IdentityGraphNodeType = "User"
	IdentityGraphNodeTypeDevice          IdentityGraphNodeType = "Device"
	IdentityGraphNodeTypeCredential      IdentityGraphNodeType = "Credential"
	IdentityGraphNodeTypeChallenge       IdentityGraphNodeType = "Challenge"
	IdentityGraphNodeTypeToken           IdentityGraphNodeType = "Token"
	IdentityGraphNodeTypeAuditAnchor     IdentityGraphNodeType = "AuditAnchor"
	IdentityGraphNodeTypePolicyScope     IdentityGraphNodeType = "PolicyScope"
	IdentityGraphNodeTypeExternalService IdentityGraphNodeType = "ExternalService"
)

type IdentityGraphEdgeType string

const (
	IdentityGraphEdgeTypeOwns          IdentityGraphEdgeType = "Owns"
	IdentityGraphEdgeTypeIssued        IdentityGraphEdgeType = "Issued"
	IdentityGraphEdgeTypeRegistered    IdentityGraphEdgeType = "Registered"
	IdentityGraphEdgeTypeBelongsTo     IdentityGraphEdgeType = "BelongsTo"
	IdentityGraphEdgeTypeAuthorizedFor IdentityGraphEdgeType = "AuthorizedFor"
	IdentityGraphEdgeTypeScopedTo      IdentityGraphEdgeType = "ScopedTo"
	IdentityGraphEdgeTypeUses          IdentityGraphEdgeType = "Uses"
	IdentityGraphEdgeTypePresentedBy   IdentityGraphEdgeType = "PresentedBy"
	IdentityGraphEdgeTypeDerivedFrom   IdentityGraphEdgeType = "DerivedFrom"
	IdentityGraphEdgeTypeApprovedBy    IdentityGraphEdgeType = "ApprovedBy"
	IdentityGraphEdgeTypeRevokedBy     IdentityGraphEdgeType = "RevokedBy"
	IdentityGraphEdgeTypeAnchoredBy    IdentityGraphEdgeType = "AnchoredBy"
	IdentityGraphEdgeTypeConnectedTo   IdentityGraphEdgeType = "ConnectedTo"
	IdentityGraphEdgeTypeObservedOn    IdentityGraphEdgeType = "ObservedOn"
)

type ExposureFindingCategory string

const (
	ExposureFindingCategoryWeakConnection    ExposureFindingCategory = "WeakConnection"
	ExposureFindingCategoryUnknownConnection ExposureFindingCategory = "UnknownConnection"
	ExposureFindingCategoryStaleCredential   ExposureFindingCategory = "StaleCredential"
	ExposureFindingCategoryHighRiskLinkage   ExposureFindingCategory = "HighRiskLinkage"
)

type ExposureFindingSeverity string

const (
	ExposureFindingSeverityLow    ExposureFindingSeverity = "Low"
	ExposureFindingSeverityMedium ExposureFindingSeverity = "Medium"
	ExposureFindingSeverityHigh   ExposureFindingSeverity = "High"
)

type IdentityGraphScores struct {
	ExposureScore          float64 `json:"exposureScore"`
	TrustScore             float64 `json:"trustScore"`
	ConnectionClarityScore float64 `json:"connectionClarityScore"`
}

type IdentityGraphNode struct {
	NodeID            string                `json:"nodeId"`
	NodeType          IdentityGraphNodeType `json:"nodeType"`
	DisplayName       string                `json:"displayName"`
	Status            string                `json:"status"`
	TrustTier         string                `json:"trustTier"`
	ObservedAtUTC     string                `json:"observedAtUtc"`
	LastVerifiedAtUTC *string               `json:"lastVerifiedAtUtc"`
	Metadata          map[string]*string    `json:"metadata"`
}

type IdentityGraphEdge struct {
	EdgeID            string                `json:"edgeId"`
	EdgeType          IdentityGraphEdgeType `json:"edgeType"`
	FromNodeID        string                `json:"fromNodeId"`
	ToNodeID          string                `json:"toNodeId"`
	Status            string                `json:"status"`
	TrustWeight       float64               `json:"trustWeight"`
	EvidenceType      string                `json:"evidenceType"`
	Reason            string                `json:"reason"`
	ObservedAtUTC     string                `json:"observedAtUtc"`
	LastVerifiedAtUTC *string               `json:"lastVerifiedAtUtc"`
	Metadata          map[string]*string    `json:"metadata"`
}

type IdentityGraphSnapshot struct {
	GraphID        string              `json:"graphId"`
	GeneratedAtUTC string              `json:"generatedAtUtc"`
	Scores         IdentityGraphScores `json:"scores"`
	Nodes          []IdentityGraphNode `json:"nodes"`
	Edges          []IdentityGraphEdge `json:"edges"`
	Metadata       map[string]*string  `json:"metadata"`
}

type ExposureFinding struct {
	FindingID string                  `json:"findingId"`
	Category  ExposureFindingCategory `json:"category"`
	Severity  ExposureFindingSeverity `json:"severity"`
	Summary   string                  `json:"summary"`
	NodeID    *string                 `json:"nodeId"`
	EdgeID    *string                 `json:"edgeId"`
	Metadata  map[string]*string      `json:"metadata"`
}

type ExposureSummary struct {
	GraphID        string            `json:"graphId"`
	GeneratedAtUTC string            `json:"generatedAtUtc"`
	ExposureScore  float64           `json:"exposureScore"`
	Findings       []ExposureFinding `json:"findings"`
	SummaryText    string            `json:"summaryText"`
}

type PerformIdentityActionRequest struct {
	SubjectID    string             `json:"subjectId"`
	ActionType   IdentityActionType `json:"actionType"`
	TargetNodeID *string            `json:"targetNodeId,omitempty"`
	Reason       *string            `json:"reason,omitempty"`
}

type IdentityActionRecord struct {
	ActionID       string               `json:"actionId"`
	SubjectID      string               `json:"subjectId"`
	ActionType     IdentityActionType   `json:"actionType"`
	Status         IdentityActionStatus `json:"status"`
	TargetNodeID   *string              `json:"targetNodeId"`
	Reason         *string              `json:"reason"`
	RequestedAtUTC string               `json:"requestedAtUtc"`
	ReversedAtUTC  *string              `json:"reversedAtUtc"`
	ReverseReason  *string              `json:"reverseReason"`
	Metadata       map[string]*string   `json:"metadata"`
}

type ScanIdentityResult struct {
	SubjectID     string                 `json:"subjectId"`
	Graph         IdentityGraphSnapshot  `json:"graph"`
	Exposure      ExposureSummary        `json:"exposure"`
	ActionHistory []IdentityActionRecord `json:"actionHistory"`
}

type BudgetEnvelope struct {
	ControlType        string `json:"controlType"`
	SubjectKey         string `json:"subjectKey"`
	WindowStartedAtUTC string `json:"windowStartedAtUtc"`
	WindowEndsAtUTC    string `json:"windowEndsAtUtc"`
	Limit              int    `json:"limit"`
	Consumed           int    `json:"consumed"`
	Remaining          int    `json:"remaining"`
	IsExhausted        bool   `json:"isExhausted"`
}
