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
    """A refusal or failure reported by the Aegir API.

    ``code`` is an :class:`AegirErrorCode` when the server used one of the common codes, and the
    server's own string otherwise. The set is deliberately open: the API reports specific
    reasons such as ``envelope_rejected`` and ``provider_not_permitted``, and collapsing those
    to ``unknown_error`` would throw away the only thing that says what actually went wrong.
    Because :class:`AegirErrorCode` is a :class:`~enum.StrEnum`, comparing against either the
    enum member or the plain string works in both cases.
    """

    def __init__(self, message: str, status: int, code: str, correlationId: str | None, body):
        super().__init__(message)
        self.status = status
        try:
            self.code = AegirErrorCode(code)
        except ValueError:
            self.code = code
        self.correlationId = correlationId
        self.body = body
