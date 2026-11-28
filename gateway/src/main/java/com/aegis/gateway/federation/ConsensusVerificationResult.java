package com.aegis.gateway.federation;

import java.time.Instant;
import java.util.Map;

/**
 * Result of evaluating cross-cluster cryptographic Merkle state and consensus alignment.
 */
public record ConsensusVerificationResult(
        boolean synchronizedStatus,
        int totalNodes,
        int healthyNodeCount,
        int divergentNodeCount,
        String globalMerkleRoot,
        Map<String, String> nodeStates,
        int totalPolicies,
        int conflictCount,
        Instant lastConsensusTime
) {}
