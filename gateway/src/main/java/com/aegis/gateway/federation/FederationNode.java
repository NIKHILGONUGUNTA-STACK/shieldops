package com.aegis.gateway.federation;

import java.time.Instant;
import java.util.Map;

/**
 * Model representing an edge cluster node participating in multi-region policy federation.
 */
public record FederationNode(
        String nodeId,
        String region,
        NodeStatus status,
        String endpointUrl,
        Instant lastHeartbeat,
        long latencyMs,
        long epoch,
        String stateMerkleRoot,
        Map<String, Long> vectorClock
) {
    public enum NodeStatus {
        HEALTHY,
        SYNCING,
        DEGRADED,
        PARTITIONED
    }

    public FederationNode withHeartbeat(long latencyMs, long epoch, String merkleRoot, Map<String, Long> vClock) {
        return new FederationNode(
                this.nodeId,
                this.region,
                NodeStatus.HEALTHY,
                this.endpointUrl,
                Instant.now(),
                latencyMs,
                epoch,
                merkleRoot,
                vClock
        );
    }

    public FederationNode withStatus(NodeStatus newStatus) {
        return new FederationNode(
                this.nodeId,
                this.region,
                newStatus,
                this.endpointUrl,
                this.lastHeartbeat,
                this.latencyMs,
                this.epoch,
                this.stateMerkleRoot,
                this.vectorClock
        );
    }
}
