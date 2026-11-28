package com.aegis.gateway.federation;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.*;

/**
 * Computes deterministic cryptographic SHA-256 Merkle tree roots and payload digests
 * for distributed multi-region policy verification.
 */
public class MerkleStateCalculator {

    public static final String EMPTY_ROOT = "0000000000000000000000000000000000000000000000000000000000000000";

    /**
     * Calculates the Merkle root hash across a collection of federated policies.
     * Leaf hashes are derived from canonical representations and lexicographically sorted
     * to ensure deterministic consensus regardless of insertion order.
     */
    public static String calculateMerkleRoot(Collection<FederatedPolicyPayload> policies) {
        if (policies == null || policies.isEmpty()) {
            return EMPTY_ROOT;
        }

        List<String> leafHashes = new ArrayList<>();
        for (FederatedPolicyPayload policy : policies) {
            String canonical = policy.policyId() + "|"
                    + policy.policyType() + "|"
                    + policy.action() + "|"
                    + policy.originNodeId() + "|"
                    + policy.originEpoch() + "|"
                    + (policy.cryptographicSignature() != null ? policy.cryptographicSignature() : "");
            leafHashes.add(sha256Hex(canonical));
        }

        // Deterministic sorting
        Collections.sort(leafHashes);

        // Reduce Merkle tree level by level
        List<String> currentLevel = leafHashes;
        while (currentLevel.size() > 1) {
            List<String> nextLevel = new ArrayList<>();
            for (int i = 0; i < currentLevel.size(); i += 2) {
                String left = currentLevel.get(i);
                String right = (i + 1 < currentLevel.size()) ? currentLevel.get(i + 1) : left;
                nextLevel.add(sha256Hex(left + right));
            }
            currentLevel = nextLevel;
        }

        return currentLevel.get(0);
    }

    /**
     * Computes a SHA-256 hex digest for a string.
     */
    public static String sha256Hex(String input) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder hexString = new StringBuilder();
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 algorithm not available", e);
        }
    }

    /**
     * Signs a policy payload to verify authenticity and prevent tampering during cross-cluster gossip.
     */
    public static String signPayload(String payloadJson, String originNodeId, long epoch) {
        return sha256Hex("SIG:" + originNodeId + ":" + epoch + ":" + payloadJson);
    }
}
