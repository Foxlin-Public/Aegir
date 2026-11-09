package cloud.foxlin.aegir.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public final class PortableSecurity
{
    private PortableSecurity()
    {
    }

    public static final class TrustCoreAlgorithmDescriptor
    {
        private final String algorithmId;
        private final boolean hybrid;

        public TrustCoreAlgorithmDescriptor(String algorithmId, boolean hybrid)
        {
            this.algorithmId = algorithmId;
            this.hybrid = hybrid;
        }

        public String getAlgorithmId() { return algorithmId; }
        public boolean isHybrid() { return hybrid; }
    }

    public static final class TrustCoreSignatureEnvelope
    {
        private final String keyId;
        private final TrustCoreAlgorithmDescriptor algorithm;
        private final byte[] signatureBytes;

        public TrustCoreSignatureEnvelope(String keyId, TrustCoreAlgorithmDescriptor algorithm, byte[] signatureBytes)
        {
            this.keyId = keyId;
            this.algorithm = algorithm;
            this.signatureBytes = signatureBytes;
        }

        public String getKeyId() { return keyId; }
        public TrustCoreAlgorithmDescriptor getAlgorithm() { return algorithm; }
        public byte[] getSignatureBytes() { return signatureBytes; }
    }

    public static final class SafeEnvelopeRecord
    {
        private final String envelopeId;
        private final String payloadType;
        private final String canonicalPayload;
        private final String payloadHash;
        private final String createdAtUtc;
        private final TrustCoreSignatureEnvelope signatureEnvelope;

        public SafeEnvelopeRecord(String envelopeId, String payloadType, String canonicalPayload, String payloadHash, String createdAtUtc, TrustCoreSignatureEnvelope signatureEnvelope)
        {
            this.envelopeId = envelopeId;
            this.payloadType = payloadType;
            this.canonicalPayload = canonicalPayload;
            this.payloadHash = payloadHash;
            this.createdAtUtc = createdAtUtc;
            this.signatureEnvelope = signatureEnvelope;
        }

        public String getEnvelopeId() { return envelopeId; }
        public String getPayloadType() { return payloadType; }
        public String getCanonicalPayload() { return canonicalPayload; }
        public String getPayloadHash() { return payloadHash; }
        public String getCreatedAtUtc() { return createdAtUtc; }
        public TrustCoreSignatureEnvelope getSignatureEnvelope() { return signatureEnvelope; }
    }

    public static final class SafeEnvelopeValidationResult
    {
        private final boolean valid;
        private final String reason;

        public SafeEnvelopeValidationResult(boolean valid, String reason)
        {
            this.valid = valid;
            this.reason = reason;
        }

        /** Always false: this portable envelope is integrity-only. */
        public boolean isAuthenticated() { return false; }
        public boolean isValid() { return valid; }
        public String getReason() { return reason; }
    }

    public static SafeEnvelopeRecord createSafeEnvelope(String payloadType, String canonicalPayload, TrustCoreSignatureEnvelope signatureEnvelope)
    {
        if (payloadType == null || payloadType.trim().isEmpty())
        {
            throw new IllegalArgumentException("payloadType is required");
        }
        if (canonicalPayload == null || canonicalPayload.trim().isEmpty())
        {
            throw new IllegalArgumentException("canonicalPayload is required");
        }

        return new SafeEnvelopeRecord(runtimeId("env"), payloadType, canonicalPayload, payloadHash(canonicalPayload), Instant.now().toString(), signatureEnvelope);
    }

    public static SafeEnvelopeValidationResult validateSafeEnvelope(SafeEnvelopeRecord envelope)
    {
        if (!payloadHash(envelope.getCanonicalPayload()).equals(envelope.getPayloadHash()))
        {
            return new SafeEnvelopeValidationResult(false, "payload_hash_mismatch");
        }

        if (envelope.getSignatureEnvelope() != null)
        {
            return new SafeEnvelopeValidationResult(false, "unsupported_signature");
        }

        return new SafeEnvelopeValidationResult(true, "integrity_only");
    }

    /** SHA-256 of exact bytes, as lowercase hex. Integrity only; no authentication. */
    public static String computePayloadDigest(byte[] payload)
    {
        try
        {
            byte[] hash = MessageDigest.getInstance("SHA-256").digest(payload);
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte value : hash) builder.append(String.format("%02x", value));
            return builder.toString();
        }
        catch (NoSuchAlgorithmException ex) { throw new IllegalStateException("SHA-256 is required.", ex); }
    }

    /** @deprecated Unsupported keyless authority; always throws. */
    @Deprecated
    public static byte[] signChallengePayload(byte[] payload)
    {
        throw new UnsupportedOperationException("Keyless signing is unsupported. Use an authorized keyed signing contract.");
    }

    /** @deprecated Unsupported keyless authority; always rejects historical or fabricated digests. */
    @Deprecated
    public static boolean verifyChallengePayload(byte[] payload, byte[] signature)
    {
        return false;
    }

    /** @deprecated Unsupported keyless authority; always throws. */
    @Deprecated
    public static byte[] signProofReceiptPayload(byte[] payload)
    {
        throw new UnsupportedOperationException("Keyless signing is unsupported. Use an authorized keyed signing contract.");
    }

    /** @deprecated Unsupported keyless authority; always rejects historical or fabricated digests. */
    @Deprecated
    public static boolean verifyProofReceiptPayload(byte[] payload, byte[] signature)
    {
        return false;
    }

    /** @deprecated Unsupported keyless authority; always throws. */
    @Deprecated
    public static byte[] signIdentityTokenPayload(byte[] payload)
    {
        throw new UnsupportedOperationException("Keyless signing is unsupported. Use an authorized keyed signing contract.");
    }

    /** @deprecated Unsupported keyless authority; always rejects historical or fabricated digests. */
    @Deprecated
    public static boolean verifyIdentityTokenPayload(byte[] payload, byte[] signature)
    {
        return false;
    }

    public static final class AgentToAgentMessageRecord
    {
        private final String messageId;
        private final String senderAgentId;
        private final String recipientAgentId;
        private final String messageType;
        private final String correlationId;
        private final SafeEnvelopeRecord envelope;
        private final String sentAtUtc;
        private final String receivedAtUtc;

        public AgentToAgentMessageRecord(String messageId, String senderAgentId, String recipientAgentId, String messageType, String correlationId, SafeEnvelopeRecord envelope, String sentAtUtc, String receivedAtUtc)
        {
            this.messageId = messageId;
            this.senderAgentId = senderAgentId;
            this.recipientAgentId = recipientAgentId;
            this.messageType = messageType;
            this.correlationId = correlationId;
            this.envelope = envelope;
            this.sentAtUtc = sentAtUtc;
            this.receivedAtUtc = receivedAtUtc;
        }

        public String getMessageId() { return messageId; }
        public String getSenderAgentId() { return senderAgentId; }
        public String getRecipientAgentId() { return recipientAgentId; }
        public String getMessageType() { return messageType; }
        public String getCorrelationId() { return correlationId; }
        public SafeEnvelopeRecord getEnvelope() { return envelope; }
        public String getSentAtUtc() { return sentAtUtc; }
        public String getReceivedAtUtc() { return receivedAtUtc; }
    }

    public static final class AgentToAgentReceiveResult
    {
        private final boolean accepted;
        private final String reason;
        private final AgentToAgentMessageRecord message;

        public AgentToAgentReceiveResult(boolean accepted, String reason, AgentToAgentMessageRecord message)
        {
            this.accepted = accepted;
            this.reason = reason;
            this.message = message;
        }

        public boolean isAccepted() { return accepted; }
        public String getReason() { return reason; }
        public AgentToAgentMessageRecord getMessage() { return message; }
    }

    public static final class InMemoryAgentToAgentProtocol
    {
        private final Map<String, List<AgentToAgentMessageRecord>> inbox = new HashMap<>();

        public AgentToAgentMessageRecord send(String senderAgentId, String recipientAgentId, String messageType, String canonicalPayload, String correlationId, TrustCoreSignatureEnvelope signatureEnvelope)
        {
            if (senderAgentId == null || senderAgentId.trim().isEmpty())
            {
                throw new IllegalArgumentException("senderAgentId is required");
            }
            if (recipientAgentId == null || recipientAgentId.trim().isEmpty())
            {
                throw new IllegalArgumentException("recipientAgentId is required");
            }
            if (messageType == null || messageType.trim().isEmpty())
            {
                throw new IllegalArgumentException("messageType is required");
            }

            AgentToAgentMessageRecord message = new AgentToAgentMessageRecord(
                runtimeId("msg"),
                senderAgentId,
                recipientAgentId,
                messageType,
                correlationId != null && !correlationId.trim().isEmpty() ? correlationId : runtimeId("corr"),
                createSafeEnvelope("agent:" + messageType, canonicalPayload, signatureEnvelope),
                Instant.now().toString(),
                null);

            List<AgentToAgentMessageRecord> messages = inbox.computeIfAbsent(recipientAgentId, ignored -> new ArrayList<>());
            messages.add(message);
            messages.sort(Comparator.comparing(AgentToAgentMessageRecord::getSentAtUtc));
            return message;
        }

        public List<AgentToAgentMessageRecord> getInbox(String recipientAgentId)
        {
            return inbox.getOrDefault(recipientAgentId, new ArrayList<>());
        }

        public AgentToAgentReceiveResult receive(String recipientAgentId, String messageId)
        {
            List<AgentToAgentMessageRecord> messages = inbox.getOrDefault(recipientAgentId, List.of());
            for (int i = 0; i < messages.size(); i++)
            {
                AgentToAgentMessageRecord message = messages.get(i);
                if (!message.getMessageId().equals(messageId))
                {
                    continue;
                }

                SafeEnvelopeValidationResult validation = validateSafeEnvelope(message.getEnvelope());
                if (!validation.isValid())
                {
                    return new AgentToAgentReceiveResult(false, validation.getReason(), message);
                }

                AgentToAgentMessageRecord accepted = new AgentToAgentMessageRecord(
                    message.getMessageId(),
                    message.getSenderAgentId(),
                    message.getRecipientAgentId(),
                    message.getMessageType(),
                    message.getCorrelationId(),
                    message.getEnvelope(),
                    message.getSentAtUtc(),
                    Instant.now().toString());
                messages.set(i, accepted);
                return new AgentToAgentReceiveResult(true, "accepted", accepted);
            }

            return new AgentToAgentReceiveResult(false, "message_not_found", null);
        }
    }

    public static final class BudgetEnvelope
    {
        private final String controlType;
        private final String subjectKey;
        private final String windowStartedAtUtc;
        private final String windowEndsAtUtc;
        private final int limit;
        private final int consumed;
        private final int remaining;
        private final boolean exhausted;

        public BudgetEnvelope(String controlType, String subjectKey, String windowStartedAtUtc, String windowEndsAtUtc, int limit, int consumed, int remaining, boolean exhausted)
        {
            this.controlType = controlType;
            this.subjectKey = subjectKey;
            this.windowStartedAtUtc = windowStartedAtUtc;
            this.windowEndsAtUtc = windowEndsAtUtc;
            this.limit = limit;
            this.consumed = consumed;
            this.remaining = remaining;
            this.exhausted = exhausted;
        }

        public String getControlType() { return controlType; }
        public String getSubjectKey() { return subjectKey; }
        public String getWindowStartedAtUtc() { return windowStartedAtUtc; }
        public String getWindowEndsAtUtc() { return windowEndsAtUtc; }
        public int getLimit() { return limit; }
        public int getConsumed() { return consumed; }
        public int getRemaining() { return remaining; }
        public boolean isExhausted() { return exhausted; }
    }

    public static final class BudgetExhaustedError extends RuntimeException
    {
        private final BudgetEnvelope envelope;

        public BudgetExhaustedError(BudgetEnvelope envelope)
        {
            super("Budget exhausted for " + envelope.getControlType() + " on '" + envelope.getSubjectKey() + "'.");
            this.envelope = envelope;
        }

        public BudgetEnvelope getEnvelope() { return envelope; }
    }

    public static final class InMemoryBudgetEnvelopeService
    {
        private final Map<String, CounterState> counters = new HashMap<>();
        private final Map<String, Integer> limits;
        private final long windowMillis;

        public InMemoryBudgetEnvelopeService()
        {
            this(new BudgetEnvelopeOptions());
        }

        public InMemoryBudgetEnvelopeService(long windowMillis)
        {
            this(new BudgetEnvelopeOptions(25, 50, 10, windowMillis));
        }

        public InMemoryBudgetEnvelopeService(BudgetEnvelopeOptions options)
        {
            BudgetEnvelopeOptions resolved = options == null ? new BudgetEnvelopeOptions() : options;
            this.limits = Map.of(
                "IdentityScan", resolved.getIdentityScanLimit(),
                "ExternalLookup", resolved.getExternalLookupLimit(),
                "ConnectionGraphRebuild", resolved.getConnectionGraphRebuildLimit());
            this.windowMillis = resolved.getWindowMs();
        }

        public BudgetEnvelope getEnvelope(String controlType, String subjectKey)
        {
            CounterState state = counters.getOrDefault(budgetKey(controlType, subjectKey), new CounterState(Instant.now(), 0));
            return toBudgetEnvelope(controlType, subjectKey, state);
        }

        public BudgetEnvelope consume(String controlType, String subjectKey)
        {
            String key = budgetKey(controlType, subjectKey);
            Instant now = Instant.now();
            CounterState current = counters.getOrDefault(key, new CounterState(now, 0));
            CounterState updated =
                now.toEpochMilli() - current.windowStartedAt.toEpochMilli() >= windowMillis
                    ? new CounterState(now, 1)
                    : new CounterState(current.windowStartedAt, current.consumed + 1);
            counters.put(key, updated);

            BudgetEnvelope envelope = toBudgetEnvelope(controlType, subjectKey, updated);
            if (updated.consumed > envelope.getLimit())
            {
                throw new BudgetExhaustedError(envelope);
            }

            return envelope;
        }

        private BudgetEnvelope toBudgetEnvelope(String controlType, String subjectKey, CounterState state)
        {
            int limit = limits.get(controlType);
            int remaining = Math.max(limit - state.consumed, 0);
            return new BudgetEnvelope(
                controlType,
                subjectKey.trim(),
                state.windowStartedAt.toString(),
                state.windowStartedAt.plusMillis(windowMillis).toString(),
                limit,
                state.consumed,
                remaining,
                state.consumed >= limit);
        }
    }

    public static final class BudgetEnvelopeOptions
    {
        private final int identityScanLimit;
        private final int externalLookupLimit;
        private final int connectionGraphRebuildLimit;
        private final long windowMs;

        public BudgetEnvelopeOptions()
        {
            this(25, 50, 10, 60_000L);
        }

        public BudgetEnvelopeOptions(int identityScanLimit, int externalLookupLimit, int connectionGraphRebuildLimit, long windowMs)
        {
            this.identityScanLimit = identityScanLimit;
            this.externalLookupLimit = externalLookupLimit;
            this.connectionGraphRebuildLimit = connectionGraphRebuildLimit;
            this.windowMs = windowMs;
        }

        public int getIdentityScanLimit() { return identityScanLimit; }
        public int getExternalLookupLimit() { return externalLookupLimit; }
        public int getConnectionGraphRebuildLimit() { return connectionGraphRebuildLimit; }
        public long getWindowMs() { return windowMs; }
    }

    private static final class CounterState
    {
        private final Instant windowStartedAt;
        private final int consumed;

        private CounterState(Instant windowStartedAt, int consumed)
        {
            this.windowStartedAt = windowStartedAt;
            this.consumed = consumed;
        }
    }

    private static String payloadHash(String canonicalPayload)
    {
        try
        {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(canonicalPayload.getBytes(StandardCharsets.UTF_8));
            StringBuilder builder = new StringBuilder(hash.length * 2);
            for (byte value : hash)
            {
                builder.append(String.format("%02x", value));
            }
            return builder.toString();
        }
        catch (NoSuchAlgorithmException ex)
        {
            throw new IllegalStateException("SHA-256 is required.", ex);
        }
    }

    private static String runtimeId(String prefix)
    {
        return prefix + "_" + System.nanoTime();
    }

    private static String budgetKey(String controlType, String subjectKey)
    {
        if (subjectKey == null || subjectKey.trim().isEmpty())
        {
            throw new IllegalArgumentException("subjectKey is required");
        }

        return controlType + ":" + subjectKey.trim();
    }
}
