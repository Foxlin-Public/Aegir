package aegirsecurity

import "fmt"

type AegirErrorCode string

const (
	AegirErrorCodeInvalidRequest  AegirErrorCode = "invalid_request"
	AegirErrorCodeUnauthorized    AegirErrorCode = "unauthorized"
	AegirErrorCodeForbidden       AegirErrorCode = "forbidden"
	AegirErrorCodeNotFound        AegirErrorCode = "not_found"
	AegirErrorCodeConflict        AegirErrorCode = "conflict"
	AegirErrorCodeRateLimited     AegirErrorCode = "rate_limited"
	AegirErrorCodeBudgetExhausted AegirErrorCode = "budget_exhausted"
	AegirErrorCodeServerError     AegirErrorCode = "server_error"
	AegirErrorCodeTransportError  AegirErrorCode = "transport_error"
	AegirErrorCodeUnknownError    AegirErrorCode = "unknown_error"
)

type AegirSecurityError struct {
	Status        int
	Code          AegirErrorCode
	CorrelationID string
	Body          string
}

func (e *AegirSecurityError) Error() string {
	return fmt.Sprintf("Aegir request failed with status %d.", e.Status)
}
