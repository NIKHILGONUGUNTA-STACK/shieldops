package com.aegis.gateway.federation;

import com.aegis.gateway.soar.DynamicWafService;
import com.aegis.gateway.soar.TokenRevocationService;
import com.aegis.gateway.workflow.WorkflowStateService;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
class FederationSyncServiceTest {

    @Mock
    private DynamicWafService dynamicWafService;

    @Mock
    private TokenRevocationService tokenRevocationService;

    @Mock
    private WorkflowStateService workflowStateService;

    private FederationSyncService syncService;

    @BeforeEach
    void setUp() {
        syncService = new FederationSyncService(
                dynamicWafService,
                tokenRevocationService,
                workflowStateService,
                new ObjectMapper()
        );
    }

    @Test
    @DisplayName("Initializes with default cluster nodes, seed policies, and synchronized consensus")
    void testInitialization() {
        List<FederationNode> nodes = syncService.getNodes();
        assertEquals(3, nodes.size(), "Should initialize with 3 cross-region nodes");

        List<FederatedPolicyPayload> policies = syncService.getPolicies();
        assertTrue(policies.size() >= 2, "Should initialize with seed WAF and Token policies");

        ConsensusVerificationResult consensus = syncService.getConsensusStatus();
        assertTrue(consensus.synchronizedStatus(), "Initial cluster should be synchronized");
        assertEquals(0, consensus.divergentNodeCount());
        assertNotNull(consensus.globalMerkleRoot());
        assertEquals(64, consensus.globalMerkleRoot().length());
    }

    @Test
    @DisplayName("Heartbeat telemetry updates node status and latency")
    void testRecordHeartbeat() {
        FederationNode updated = syncService.recordHeartbeat(
                "node-eu-central-dr",
                45L,
                105L,
                null,
                Map.of("node-eu-central-dr", 105L)
        );

        assertNotNull(updated);
        assertEquals(45L, updated.latencyMs());
        assertEquals(105L, updated.epoch());

        Optional<FederationNode> retrieved = syncService.getNode("node-eu-central-dr");
        assertTrue(retrieved.isPresent());
        assertEquals(45L, retrieved.get().latencyMs());
    }

    @Test
    @DisplayName("Broadcast policy increments epoch, applies locally, and updates Merkle root")
    void testBroadcastPolicy() {
        long initialEpoch = syncService.getCurrentEpoch();
        String initialRoot = syncService.getConsensusStatus().globalMerkleRoot();

        String payloadJson = "{\"ip\":\"203.0.113.50\",\"reason\":\"Cross-region botnet\",\"incidentId\":\"INC-999\"}";
        FederatedPolicyPayload created = syncService.broadcastPolicy(
                FederatedPolicyPayload.PolicyType.WAF_IP_BAN,
                FederatedPolicyPayload.PolicyAction.UPSERT,
                payloadJson
        );

        assertNotNull(created);
        assertEquals(initialEpoch + 1, created.originEpoch());
        assertEquals(syncService.getLocalNodeId(), created.originNodeId());

        ConsensusVerificationResult updatedConsensus = syncService.getConsensusStatus();
        assertNotEquals(initialRoot, updatedConsensus.globalMerkleRoot(), "Merkle root must update on new policy broadcast");
    }

    @Test
    @DisplayName("Peer policy ingestion verifies signature and rejects tampered updates")
    void testIngestPeerPayloadSignatureValidation() {
        String payloadJson = "{\"jti\":\"rogue-stolen-token\",\"subject\":\"victim.user\"}";
        String validSig = MerkleStateCalculator.signPayload(payloadJson, "node-eu-central-dr", 105);

        FederatedPolicyPayload validPayload = new FederatedPolicyPayload(
                "FED-POL-EXT-001",
                FederatedPolicyPayload.PolicyType.TOKEN_REVOCATION,
                FederatedPolicyPayload.PolicyAction.UPSERT,
                "node-eu-central-dr",
                105,
                Map.of("node-eu-central-dr", 105L),
                payloadJson,
                validSig,
                Instant.now()
        );

        boolean accepted = syncService.ingestPeerPayload(validPayload);
        assertTrue(accepted, "Valid signed payload must be accepted");

        // Tampered payload with forged signature
        FederatedPolicyPayload forgedPayload = new FederatedPolicyPayload(
                "FED-POL-FORGED-001",
                FederatedPolicyPayload.PolicyType.TOKEN_REVOCATION,
                FederatedPolicyPayload.PolicyAction.UPSERT,
                "node-eu-central-dr",
                106,
                Map.of("node-eu-central-dr", 106L),
                payloadJson,
                "bad-signature-hash",
                Instant.now()
        );

        boolean rejected = syncService.ingestPeerPayload(forgedPayload);
        assertFalse(rejected, "Forged signature payload must be rejected");
    }

    @Test
    @DisplayName("Vector clock causality drops stale updates and resolves conflicts")
    void testVectorClockConflictResolution() {
        String payloadJson = "{\"ip\":\"192.0.2.1\"}";
        String sig1 = MerkleStateCalculator.signPayload(payloadJson, "node-eu-central-dr", 110);

        FederatedPolicyPayload p1 = new FederatedPolicyPayload(
                "FED-POL-CONFLICT-01",
                FederatedPolicyPayload.PolicyType.WAF_IP_BAN,
                FederatedPolicyPayload.PolicyAction.UPSERT,
                "node-eu-central-dr",
                110,
                Map.of("node-eu-central-dr", 110L),
                payloadJson,
                sig1,
                Instant.now()
        );
        assertTrue(syncService.ingestPeerPayload(p1));

        // Stale update with lower epoch (105 < 110)
        String sigStale = MerkleStateCalculator.signPayload(payloadJson, "node-eu-central-dr", 105);
        FederatedPolicyPayload pStale = new FederatedPolicyPayload(
                "FED-POL-CONFLICT-01",
                FederatedPolicyPayload.PolicyType.WAF_IP_BAN,
                FederatedPolicyPayload.PolicyAction.UPSERT,
                "node-eu-central-dr",
                105,
                Map.of("node-eu-central-dr", 105L),
                payloadJson,
                sigStale,
                Instant.now()
        );
        assertFalse(syncService.ingestPeerPayload(pStale), "Stale payload must be discarded");
    }

    @Test
    @DisplayName("Cluster reconciliation resolves node drift and restores 100% consensus")
    void testReconciliation() {
        // Artificially simulate node drift on AP node
        syncService.recordHeartbeat(
                "node-ap-south-edge",
                120L,
                90L,
                "divergent-merkle-root-000000000000000000000000000000000000000000000000",
                Map.of("node-ap-south-edge", 90L)
        );

        ConsensusVerificationResult drifted = syncService.getConsensusStatus();
        assertFalse(drifted.synchronizedStatus(), "Cluster should detect divergence");
        assertEquals(1, drifted.divergentNodeCount());

        ConsensusVerificationResult reconciled = syncService.reconcileCluster();
        assertTrue(reconciled.synchronizedStatus(), "Reconciliation must restore synchronized consensus");
        assertEquals(0, reconciled.divergentNodeCount());
    }
}
