package com.aegis.gateway.federation;

import java.time.Instant;
import java.util.Map;

/**
 * Encapsulates a policy mutation payload propagated across federation peer clusters.
 */
public record FederatedPolicyPayload(
        String policyId,
        PolicyType policyType,
        PolicyAction action,
        String originNodeId,
        long originEpoch,
        Map<String, Long> vectorClock,
        String payloadJson,
        String cryptographicSignature,
        Instant timestamp
) {
    public enum PolicyType {
        WAF_IP_BAN,
        TOKEN_REVOCATION,
        WORKFLOW_RULE,
        ADAPTIVE_CHALLENGE
    }

    public enum PolicyAction {
        UPSERT,
        REVOKE
    }
}
