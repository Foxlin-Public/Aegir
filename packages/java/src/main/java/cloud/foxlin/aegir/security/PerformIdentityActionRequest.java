package cloud.foxlin.aegir.security;

import java.util.LinkedHashMap;
import java.util.Map;

public final class PerformIdentityActionRequest
{
    private final String subjectId;
    private final String actionType;
    private final String targetNodeId;
    private final String reason;

    public PerformIdentityActionRequest(String subjectId, SecurityModels.IdentityActionType actionType, String targetNodeId, String reason)
    {
        this(subjectId, actionType == null ? null : actionType.name(), targetNodeId, reason);
    }

    public PerformIdentityActionRequest(String subjectId, String actionType, String targetNodeId, String reason)
    {
        this.subjectId = subjectId;
        this.actionType = actionType;
        this.targetNodeId = targetNodeId;
        this.reason = reason;
    }

    public Map<String, Object> toMap()
    {
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("subjectId", subjectId);
        payload.put("actionType", actionType);

        if (targetNodeId != null)
        {
            payload.put("targetNodeId", targetNodeId);
        }

        if (reason != null)
        {
            payload.put("reason", reason);
        }

        return payload;
    }

    public String getSubjectId()
    {
        return subjectId;
    }

    public String getActionType()
    {
        return actionType;
    }

    public SecurityModels.IdentityActionType getTypedActionType()
    {
        return actionType == null ? null : SecurityModels.IdentityActionType.valueOf(actionType);
    }

    public String getTargetNodeId()
    {
        return targetNodeId;
    }

    public String getReason()
    {
        return reason;
    }
}
