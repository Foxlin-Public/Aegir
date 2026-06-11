package cloud.foxlin.aegir.security;

public final class AegirSecurityError extends RuntimeException
{
    private final int status;
    private final String code;
    private final AegirErrorCode errorCode;
    private final String correlationId;
    private final Object body;

    public AegirSecurityError(String message, int status, String code, String correlationId, Object body)
    {
        super(message);
        this.status = status;
        this.code = code;
        this.errorCode = AegirErrorCode.fromCode(code);
        this.correlationId = correlationId;
        this.body = body;
    }

    public int getStatus()
    {
        return status;
    }

    public Object getBody()
    {
        return body;
    }

    public String getCode()
    {
        return code;
    }

    public AegirErrorCode getErrorCode()
    {
        return errorCode;
    }

    public String getCorrelationId()
    {
        return correlationId;
    }
}
