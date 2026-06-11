package cloud.foxlin.aegir.security;

public enum AegirErrorCode
{
    INVALID_REQUEST("invalid_request"),
    UNAUTHORIZED("unauthorized"),
    FORBIDDEN("forbidden"),
    NOT_FOUND("not_found"),
    CONFLICT("conflict"),
    RATE_LIMITED("rate_limited"),
    BUDGET_EXHAUSTED("budget_exhausted"),
    SERVER_ERROR("server_error"),
    TRANSPORT_ERROR("transport_error"),
    UNKNOWN_ERROR("unknown_error");

    private final String code;

    AegirErrorCode(String code)
    {
        this.code = code;
    }

    public String getCode()
    {
        return code;
    }

    public static AegirErrorCode fromCode(String code)
    {
        if (code != null)
        {
            for (AegirErrorCode value : values())
            {
                if (value.code.equals(code))
                {
                    return value;
                }
            }
        }

        return UNKNOWN_ERROR;
    }
}
