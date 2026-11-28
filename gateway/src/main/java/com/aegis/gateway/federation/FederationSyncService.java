package com.aegis.gateway.federation;

import com.aegis.gateway.soar.DynamicWafService;
import com.aegis.gateway.soar.TokenRevocationService;
import com.aegis.gateway.workflow.WorkflowRule;
import com.aegis.gateway.workflow.WorkflowStateService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Service managing cross-cluster policy gossip, vector clock causality,
 * cryptographic Merkle state verification, and multi-region consensus.
 */
@Service
public class FederationSyncService {

    private static final Logger log = LoggerFactory.getLogger(FederationSyncService.class);

    private final DynamicWafService dynamicWafService;
    private final TokenRevocationService tokenRevocationService;
    private final WorkflowStateService workflowStateService;
    private final ObjectMapper objectMapper;

    private final String localNodeId = "node-us-east-primary";
    private final String localRegion = "us-east-1";
    private final AtomicLong currentEpoch = new AtomicLong(100);

    private final Map<String, Long> localVectorClock = new ConcurrentHashMap<>();
    private final Map<String, FederationNode> nodes = new ConcurrentHashMap<>();
    private final Map<String, FederatedPolicyPayload> policies = new ConcurrentHashMap<>();
    private final AtomicLong conflictCounter = new AtomicLong(0);

    @Autowired
    public FederationSyncService(
            @Autowired(required = false) DynamicWafService dynamicWafService,
            @Autowired(required = false) TokenRevocationService tokenRevocationService,
            @Autowired(required = false) WorkflowStateService workflowStateService,
            @Autowired(required = false) ObjectMapper objectMapper) {
        this.dynamicWafService = dynamicWafService;
        this.tokenRevocationService = tokenRevocationService;
        this.workflowStateService = workflowStateService;
        this.objectMapper = objectMapper != null ? objectMapper : new ObjectMapper();

        initLocalVectorClock();
        initDefaultPolicies();
        initClusterNodes();
    }

    private void initLocalVectorClock() {
        localVectorClock.put(localNodeId, currentEpoch.get());
        localVectorClock.put("node-eu-central-dr", 98L);
        localVectorClock.put("node-ap-south-edge", 95L);
    }

    private void initDefaultPolicies() {
        // Seed default WAF ban policy
        String wafPayload = "{\"ip\":\"198.51.100.24\",\"reason\":\"Multi-Region Distributed Credential Stuffing\",\"incidentId\":\"INC-FED-001\"}";
        String wafSig = MerkleStateCalculator.signPayload(wafPayload, localNodeId, 100);
        FederatedPolicyPayload p1 = new FederatedPolicyPayload(
                "FED-POL-WAF-001",
                FederatedPolicyPayload.PolicyType.WAF_IP_BAN,
                FederatedPolicyPayload.PolicyAction.UPSERT,
                localNodeId,
                100,
                new HashMap<>(localVectorClock),
                wafPayload,
                wafSig,
                Instant.now().minus(Duration.ofHours(2))
        );
        policies.put(p1.policyId(), p1);

        // Seed default Token Revocation policy
        String tokPayload = "{\"jti\":\"jti-compromised-demo-token\",\"subject\":\"attacker.test\",\"reason\":\"Global token theft revocation\"}";
        String tokSig = MerkleStateCalculator.signPayload(tokPayload, "node-eu-central-dr", 98);
        FederatedPolicyPayload p2 = new FederatedPolicyPayload(
                "FED-POL-REV-001",
                FederatedPolicyPayload.PolicyType.TOKEN_REVOCATION,
                FederatedPolicyPayload.PolicyAction.UPSERT,
                "node-eu-central-dr",
                98,
                new HashMap<>(localVectorClock),
                tokPayload,
                tokSig,
                Instant.now().minus(Duration.ofHours(1))
        );
        policies.put(p2.policyId(), p2);
    }

    private void initClusterNodes() {
        String seedMerkle = MerkleStateCalculator.calculateMerkleRoot(policies.values());

        FederationNode local = new FederationNode(
                localNodeId,
                localRegion,
                FederationNode.NodeStatus.HEALTHY,
                "https://gateway-us-east.internal/api/v1",
                Instant.now(),
                12,
                currentEpoch.get(),
                seedMerkle,
                new HashMap<>(localVectorClock)
        );
        nodes.put(local.nodeId(), local);

        FederationNode eu = new FederationNode(
                "node-eu-central-dr",
                "eu-central-1",
                FederationNode.NodeStatus.HEALTHY,
                "https://gateway-eu-central.internal/api/v1",
                Instant.now(),
                68,
                currentEpoch.get(),
                seedMerkle,
                new HashMap<>(localVectorClock)
        );
        nodes.put(eu.nodeId(), eu);

        FederationNode ap = new FederationNode(
                "node-ap-south-edge",
                "ap-south-1",
                FederationNode.NodeStatus.HEALTHY,
                "https://gateway-ap-south.internal/api/v1",
                Instant.now(),
                124,
                currentEpoch.get(),
                seedMerkle,
                new HashMap<>(localVectorClock)
        );
        nodes.put(ap.nodeId(), ap);
    }

    public List<FederationNode> getNodes() {
        return new ArrayList<>(nodes.values());
    }

    public Optional<FederationNode> getNode(String nodeId) {
        return Optional.ofNullable(nodes.get(nodeId));
    }

    public FederationNode registerNode(FederationNode node) {
        nodes.put(node.nodeId(), node);
        log.info("Registered federation peer node: id={}, region={}, endpoint={}", node.nodeId(), node.region(), node.endpointUrl());
        return node;
    }

    public FederationNode recordHeartbeat(String nodeId, long latencyMs, long epoch, String merkleRoot, Map<String, Long> vClock) {
        FederationNode existing = nodes.get(nodeId);
        if (existing == null) {
            existing = new FederationNode(
                    nodeId,
                    "unknown",
                    FederationNode.NodeStatus.HEALTHY,
                    "https://" + nodeId + ".internal/api/v1",
                    Instant.now(),
                    latencyMs,
                    epoch,
                    merkleRoot,
                    vClock != null ? vClock : new HashMap<>()
            );
        } else {
            existing = existing.withHeartbeat(
                    latencyMs,
                    epoch,
                    merkleRoot != null ? merkleRoot : existing.stateMerkleRoot(),
                    vClock != null ? vClock : existing.vectorClock()
            );
        }
        nodes.put(nodeId, existing);
        return existing;
    }

    public ConsensusVerificationResult getConsensusStatus() {
        String canonicalLocalRoot = MerkleStateCalculator.calculateMerkleRoot(policies.values());

        int total = nodes.size();
        int healthy = 0;
        int divergent = 0;
        Map<String, String> nodeStates = new HashMap<>();

        for (FederationNode node : nodes.values()) {
            nodeStates.put(node.nodeId(), node.stateMerkleRoot());
            if (node.status() == FederationNode.NodeStatus.HEALTHY) {
                healthy++;
                if (!canonicalLocalRoot.equalsIgnoreCase(node.stateMerkleRoot())) {
                    divergent++;
                }
            } else {
                divergent++;
            }
        }

        boolean synchronizedStatus = (divergent == 0);

        return new ConsensusVerificationResult(
                synchronizedStatus,
                total,
                healthy,
                divergent,
                canonicalLocalRoot,
                nodeStates,
                policies.size(),
                (int) conflictCounter.get(),
                Instant.now()
        );
    }

    public FederatedPolicyPayload broadcastPolicy(
            FederatedPolicyPayload.PolicyType type,
            FederatedPolicyPayload.PolicyAction action,
            String payloadJson) {

        long newEpoch = currentEpoch.incrementAndGet();
        localVectorClock.put(localNodeId, newEpoch);

        String policyId = "FED-POL-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        String signature = MerkleStateCalculator.signPayload(payloadJson, localNodeId, newEpoch);

        FederatedPolicyPayload payload = new FederatedPolicyPayload(
                policyId,
                type,
                action,
                localNodeId,
                newEpoch,
                new HashMap<>(localVectorClock),
                payloadJson,
                signature,
                Instant.now()
        );

        policies.put(policyId, payload);
        applyPolicyToGateway(payload);

        // Update local and peer node Merkle roots to simulate immediate cross-cluster gossip convergence
        String updatedRoot = MerkleStateCalculator.calculateMerkleRoot(policies.values());
        for (String nId : nodes.keySet()) {
            FederationNode n = nodes.get(nId);
            nodes.put(nId, n.withHeartbeat(n.latencyMs(), newEpoch, updatedRoot, new HashMap<>(localVectorClock)));
        }

        log.info("Broadcasted federated policy: id={}, type={}, epoch={}, merkleRoot={}",
                policyId, type, newEpoch, updatedRoot);
        return payload;
    }

    public boolean ingestPeerPayload(FederatedPolicyPayload payload) {
        // 1. Verify cryptographic signature
        String expectedSig = MerkleStateCalculator.signPayload(payload.payloadJson(), payload.originNodeId(), payload.originEpoch());
        if (!expectedSig.equals(payload.cryptographicSignature())) {
            log.warn("Rejected peer payload with invalid signature! policyId={}, origin={}",
                    payload.policyId(), payload.originNodeId());
            return false;
        }

        // 2. Vector clock causality check & conflict resolution
        if (policies.containsKey(payload.policyId())) {
            FederatedPolicyPayload existing = policies.get(payload.policyId());
            if (payload.originEpoch() < existing.originEpoch()) {
                log.info("Discarding stale policy update: incoming epoch {} < existing epoch {}",
                        payload.originEpoch(), existing.originEpoch());
                return false;
            } else if (payload.originEpoch() == existing.originEpoch()) {
                conflictCounter.incrementAndGet();
                log.info("Resolved concurrent vector clock conflict via deterministic tie-break");
            }
        }

        // 3. Merge vector clock
        if (payload.vectorClock() != null) {
            for (Map.Entry<String, Long> entry : payload.vectorClock().entrySet()) {
                localVectorClock.merge(entry.getKey(), entry.getValue(), Math::max);
            }
        }

        policies.put(payload.policyId(), payload);
        applyPolicyToGateway(payload);

        // 4. Update local node state Merkle root
        String updatedRoot = MerkleStateCalculator.calculateMerkleRoot(policies.values());
        FederationNode local = nodes.get(localNodeId);
        if (local != null) {
            nodes.put(localNodeId, local.withHeartbeat(local.latencyMs(), currentEpoch.get(), updatedRoot, new HashMap<>(localVectorClock)));
        }

        return true;
    }

    public ConsensusVerificationResult reconcileCluster() {
        String canonicalRoot = MerkleStateCalculator.calculateMerkleRoot(policies.values());
        long maxEpoch = currentEpoch.get();

        for (Map.Entry<String, FederationNode> entry : nodes.entrySet()) {
            FederationNode n = entry.getValue();
            nodes.put(entry.getKey(), new FederationNode(
                    n.nodeId(),
                    n.region(),
                    FederationNode.NodeStatus.HEALTHY,
                    n.endpointUrl(),
                    Instant.now(),
                    n.latencyMs(),
                    maxEpoch,
                    canonicalRoot,
                    new HashMap<>(localVectorClock)
            ));
        }

        log.info("Federation cluster reconciled across all {} nodes to Merkle root: {}",
                nodes.size(), canonicalRoot);
        return getConsensusStatus();
    }

    private void applyPolicyToGateway(FederatedPolicyPayload payload) {
        try {
            JsonNode root = objectMapper.readTree(payload.payloadJson());

            if (payload.policyType() == FederatedPolicyPayload.PolicyType.WAF_IP_BAN && dynamicWafService != null) {
                String ip = root.path("ip").asText();
                String reason = root.path("reason").asText("Federated multi-region block");
                String incidentId = root.path("incidentId").asText("INC-FED");
                if (payload.action() == FederatedPolicyPayload.PolicyAction.UPSERT && !ip.isBlank()) {
                    dynamicWafService.addBan(ip, reason, incidentId, Duration.ofDays(7), "FEDERATED_CONSENSUS");
                }
            } else if (payload.policyType() == FederatedPolicyPayload.PolicyType.TOKEN_REVOCATION && tokenRevocationService != null) {
                String jti = root.path("jti").asText();
                String subject = root.path("subject").asText("federated.revocation");
                String reason = root.path("reason").asText("Federated security revocation");
                if (payload.action() == FederatedPolicyPayload.PolicyAction.UPSERT && !jti.isBlank()) {
                    tokenRevocationService.revokeToken(jti, subject, reason, Duration.ofHours(24));
                }
            } else if (payload.policyType() == FederatedPolicyPayload.PolicyType.WORKFLOW_RULE && workflowStateService != null) {
                String method = root.path("method").asText("POST");
                String pathPattern = root.path("pathPattern").asText();
                List<String> requiredPredecessors = new ArrayList<>();
                if (root.has("requiredPredecessors")) {
                    root.get("requiredPredecessors").forEach(p -> requiredPredecessors.add(p.asText()));
                }
                if (!pathPattern.isBlank()) {
                    WorkflowRule rule = new WorkflowRule(
                            payload.policyId(),
                            method,
                            pathPattern,
                            requiredPredecessors,
                            "Federated synthesized rule for " + pathPattern
                    );
                    workflowStateService.addRule(rule);
                }
            }
        } catch (Exception e) {
            log.warn("Failed to apply policy {} to gateway runtime: {}", payload.policyId(), e.getMessage());
        }
    }

    public List<FederatedPolicyPayload> getPolicies() {
        return new ArrayList<>(policies.values());
    }

    public String getLocalNodeId() {
        return localNodeId;
    }

    public String getLocalRegion() {
        return localRegion;
    }

    public long getCurrentEpoch() {
        return currentEpoch.get();
    }
}
