package com.aegis.gateway.federation;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;

class MerkleStateCalculatorTest {

    @Test
    @DisplayName("Empty policies return standard 64-character zero hex root")
    void testEmptyPoliciesRoot() {
        String root = MerkleStateCalculator.calculateMerkleRoot(Collections.emptyList());
        assertEquals("0000000000000000000000000000000000000000000000000000000000000000", root);
        assertEquals(64, root.length());
    }

    @Test
    @DisplayName("Merkle root calculation is deterministic and order-invariant")
    void testDeterministicOrderInvariant() {
        FederatedPolicyPayload p1 = new FederatedPolicyPayload(
                "POL-1",
                FederatedPolicyPayload.PolicyType.WAF_IP_BAN,
                FederatedPolicyPayload.PolicyAction.UPSERT,
                "node-1",
                100,
                Map.of("node-1", 100L),
                "{\"ip\":\"10.0.0.1\"}",
                "sig1",
                Instant.now()
        );

        FederatedPolicyPayload p2 = new FederatedPolicyPayload(
                "POL-2",
                FederatedPolicyPayload.PolicyType.TOKEN_REVOCATION,
                FederatedPolicyPayload.PolicyAction.UPSERT,
                "node-2",
                101,
                Map.of("node-2", 101L),
                "{\"jti\":\"token-abc\"}",
                "sig2",
                Instant.now()
        );

        FederatedPolicyPayload p3 = new FederatedPolicyPayload(
                "POL-3",
                FederatedPolicyPayload.PolicyType.WORKFLOW_RULE,
                FederatedPolicyPayload.PolicyAction.UPSERT,
                "node-1",
                102,
                Map.of("node-1", 102L),
                "{\"pathPattern\":\"/api/v1/test\"}",
                "sig3",
                Instant.now()
        );

        List<FederatedPolicyPayload> list1 = List.of(p1, p2, p3);
        List<FederatedPolicyPayload> list2 = List.of(p3, p1, p2); // Shuffled order

        String root1 = MerkleStateCalculator.calculateMerkleRoot(list1);
        String root2 = MerkleStateCalculator.calculateMerkleRoot(list2);

        assertNotNull(root1);
        assertEquals(64, root1.length());
        assertEquals(root1, root2, "Merkle root must be identical regardless of insertion order");
    }

    @Test
    @DisplayName("Tampering with a single policy field immediately diverges Merkle root")
    void testTamperDetection() {
        FederatedPolicyPayload original = new FederatedPolicyPayload(
                "POL-1",
                FederatedPolicyPayload.PolicyType.WAF_IP_BAN,
                FederatedPolicyPayload.PolicyAction.UPSERT,
                "node-1",
                100,
                Map.of("node-1", 100L),
                "{\"ip\":\"10.0.0.1\"}",
                "sig1",
                Instant.now()
        );

        FederatedPolicyPayload tampered = new FederatedPolicyPayload(
                "POL-1",
                FederatedPolicyPayload.PolicyType.WAF_IP_BAN,
                FederatedPolicyPayload.PolicyAction.UPSERT,
                "node-1",
                101, // Altered epoch
                Map.of("node-1", 101L),
                "{\"ip\":\"10.0.0.1\"}",
                "sig1",
                Instant.now()
        );

        String rootOriginal = MerkleStateCalculator.calculateMerkleRoot(List.of(original));
        String rootTampered = MerkleStateCalculator.calculateMerkleRoot(List.of(tampered));

        assertNotEquals(rootOriginal, rootTampered, "Tampered payload must produce a divergent Merkle root");
    }

    @Test
    @DisplayName("Payload signature verification verifies authenticity")
    void testPayloadSignature() {
        String payload = "{\"ip\":\"192.168.1.100\"}";
        String sig = MerkleStateCalculator.signPayload(payload, "node-us-east", 105);

        assertNotNull(sig);
        assertEquals(64, sig.length());
        assertEquals(sig, MerkleStateCalculator.signPayload(payload, "node-us-east", 105));
        assertNotEquals(sig, MerkleStateCalculator.signPayload(payload, "node-us-east", 106));
    }
}
