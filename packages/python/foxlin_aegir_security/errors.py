from enum import StrEnum


class AegirErrorCode(StrEnum):
    InvalidRequest = "invalid_request"
    Unauthorized = "unauthorized"
    Forbidden = "forbidden"
    NotFound = "not_found"
    Conflict = "conflict"
    RateLimited = "rate_limited"
    BudgetExhausted = "budget_exhausted"
    ServerError = "server_error"
    TransportError = "transport_error"
    UnknownError = "unknown_error"


class AegirSecurityError(Exception):
    def __init__(self, message: str, status: int, code: str, correlationId: str | None, body):
        super().__init__(message)
        self.status = status
        try:
            self.code = AegirErrorCode(code)
        except ValueError:
            self.code = AegirErrorCode.UnknownError
        self.correlationId = correlationId
        self.body = body
