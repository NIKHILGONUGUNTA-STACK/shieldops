package com.aegis.gateway.federation;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * REST API exposing Multi-Region Federated Consensus, peer heartbeats,
 * cryptographic Merkle state verification, and distributed policy synchronization.
 */
@RestController
@RequestMapping("/api/v1/security/federation")
public class FederationController {

    private final FederationSyncService federationSyncService;

    @Autowired
    public FederationController(FederationSyncService federationSyncService) {
        this.federationSyncService = federationSyncService;
    }

    // ------------------------------------------------------------------------
    // Peer Nodes & Heartbeat Telemetry
    // ------------------------------------------------------------------------

    @GetMapping("/nodes")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<List<FederationNode>> getNodes() {
        return ResponseEntity.ok(federationSyncService.getNodes());
    }

    @GetMapping("/nodes/{nodeId}")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<FederationNode> getNode(@PathVariable String nodeId) {
        Optional<FederationNode> node = federationSyncService.getNode(nodeId);
        return node.map(ResponseEntity::ok).orElseGet(() -> ResponseEntity.notFound().build());
    }

    public record RegisterNodeRequest(
            String nodeId,
            String region,
            String endpointUrl
    ) {}

    @PostMapping("/nodes/register")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<FederationNode> registerNode(@RequestBody RegisterNodeRequest request) {
        FederationNode node = new FederationNode(
                request.nodeId(),
                request.region(),
                FederationNode.NodeStatus.HEALTHY,
                request.endpointUrl(),
                Instant.now(),
                25,
                federationSyncService.getCurrentEpoch(),
                MerkleStateCalculator.calculateMerkleRoot(federationSyncService.getPolicies()),
                Map.of(request.nodeId(), federationSyncService.getCurrentEpoch())
        );
        FederationNode registered = federationSyncService.registerNode(node);
        return ResponseEntity.status(HttpStatus.CREATED).body(registered);
    }

    public record HeartbeatRequest(
            String nodeId,
            long latencyMs,
            long epoch,
            String merkleRoot,
            Map<String, Long> vectorClock
    ) {}

    @PostMapping("/heartbeat")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<FederationNode> recordHeartbeat(@RequestBody HeartbeatRequest request) {
        FederationNode updated = federationSyncService.recordHeartbeat(
                request.nodeId(),
                request.latencyMs(),
                request.epoch(),
                request.merkleRoot(),
                request.vectorClock()
        );
        return ResponseEntity.ok(updated);
    }

    // ------------------------------------------------------------------------
    // Consensus & Merkle State Verification
    // ------------------------------------------------------------------------

    @GetMapping("/consensus")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<ConsensusVerificationResult> getConsensus() {
        return ResponseEntity.ok(federationSyncService.getConsensusStatus());
    }

    @PostMapping("/reconcile")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<ConsensusVerificationResult> reconcileCluster() {
        return ResponseEntity.ok(federationSyncService.reconcileCluster());
    }

    // ------------------------------------------------------------------------
    // Federated Policies & Synchronization
    // ------------------------------------------------------------------------

    @GetMapping("/policies")
    @PreAuthorize("hasAnyRole('SECURITY_ADMIN', 'SECURITY_ANALYST')")
    public ResponseEntity<List<FederatedPolicyPayload>> getPolicies() {
        return ResponseEntity.ok(federationSyncService.getPolicies());
    }

    public record BroadcastPolicyRequest(
            FederatedPolicyPayload.PolicyType type,
            FederatedPolicyPayload.PolicyAction action,
            String payloadJson
    ) {}

    @PostMapping("/broadcast")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<FederatedPolicyPayload> broadcastPolicy(@RequestBody BroadcastPolicyRequest request) {
        FederatedPolicyPayload payload = federationSyncService.broadcastPolicy(
                request.type(),
                request.action(),
                request.payloadJson()
        );
        return ResponseEntity.status(HttpStatus.CREATED).body(payload);
    }

    @PostMapping("/sync")
    @PreAuthorize("hasRole('SECURITY_ADMIN')")
    public ResponseEntity<Map<String, Object>> ingestPeerSync(@RequestBody FederatedPolicyPayload payload) {
        boolean accepted = federationSyncService.ingestPeerPayload(payload);
        if (!accepted) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(Map.of(
                    "status", "REJECTED",
                    "reason", "Signature invalid or superseded by vector clock epoch",
                    "policyId", payload.policyId()
            ));
        }
        return ResponseEntity.ok(Map.of(
                "status", "ACCEPTED",
                "policyId", payload.policyId(),
                "consensus", federationSyncService.getConsensusStatus()
        ));
    }
}
