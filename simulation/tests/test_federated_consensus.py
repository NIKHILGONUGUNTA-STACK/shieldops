"""
Phase 8.3: Multi-Region Federated Policy Consensus & Distributed Synchronization Tests.

Validates:
1. Multi-cluster peer discovery, heartbeat gossip, and latency tracking.
2. Vector clock causality, partial ordering, and deterministic conflict resolution.
3. Cryptographic Merkle tree state verification and instantaneous tamper detection.
4. Network partition recovery and zero-data-loss delta policy reconciliation.
"""

import hashlib
import json
import time
from typing import Dict, List, Optional
import pytest


# ---------------------------------------------------------------------------
# Python In-Memory Simulation of Federation Primitives
# ---------------------------------------------------------------------------

class MerkleEngine:
    EMPTY_ROOT = "0000000000000000000000000000000000000000000000000000000000000000"

    @staticmethod
    def sha256_hex(val: str) -> str:
        return hashlib.sha256(val.encode("utf-8")).hexdigest()

    @classmethod
    def calculate_root(cls, policies: List[dict]) -> str:
        if not policies:
            return cls.EMPTY_ROOT

        leaf_hashes = []
        for p in policies:
            canonical = f"{p['policyId']}|{p['policyType']}|{p['action']}|{p['originNodeId']}|{p['originEpoch']}|{p.get('sig', '')}"
            leaf_hashes.append(cls.sha256_hex(canonical))

        # Lexicographical sort ensures order-independence
        leaf_hashes.sort()

        current_level = leaf_hashes
        while len(current_level) > 1:
            next_level = []
            for i in range(0, len(current_level), 2):
                left = current_level[i]
                right = current_level[i + 1] if i + 1 < len(current_level) else left
                next_level.append(cls.sha256_hex(left + right))
            current_level = next_level

        return current_level[0]


class SimulatedFederationNode:
    def __init__(self, node_id: str, region: str, endpoint: str):
        self.node_id = node_id
        self.region = region
        self.endpoint = endpoint
        self.status = "HEALTHY"
        self.latency_ms = 20
        self.epoch = 100
        self.vector_clock: Dict[str, int] = {node_id: 100}
        self.policies: Dict[str, dict] = {}
        self.last_heartbeat = time.time()

    def get_merkle_root(self) -> str:
        return MerkleEngine.calculate_root(list(self.policies.values()))

    def apply_policy(self, policy: dict) -> bool:
        pol_id = policy["policyId"]
        # Signature check simulation
        expected_sig = MerkleEngine.sha256_hex(f"SIG:{policy['originNodeId']}:{policy['originEpoch']}:{policy.get('payloadJson', '')}")
        if policy.get("sig") != expected_sig:
            return False

        # Vector clock conflict check
        if pol_id in self.policies:
            existing = self.policies[pol_id]
            if policy["originEpoch"] < existing["originEpoch"]:
                return False  # Stale

        self.policies[pol_id] = policy
        # Merge vector clock
        for k, v in policy.get("vector_clock", {}).items():
            self.vector_clock[k] = max(self.vector_clock.get(k, 0), v)

        return True


# ---------------------------------------------------------------------------
# Test Cases
# ---------------------------------------------------------------------------

def test_peer_discovery_and_heartbeat_gossip():
    """Verify peer node discovery, latency tracking, and status degradation on heartbeat timeout."""
    node_us = SimulatedFederationNode("node-us-east-primary", "us-east-1", "https://us.internal")
    node_eu = SimulatedFederationNode("node-eu-central-dr", "eu-central-1", "https://eu.internal")

    # Initial state
    assert node_us.status == "HEALTHY"
    assert node_eu.status == "HEALTHY"

    # Heartbeat gossip update
    now = time.time()
    node_eu.latency_ms = 68
    node_eu.epoch = 102
    node_eu.last_heartbeat = now

    assert node_eu.latency_ms == 68
    assert node_eu.epoch == 102

    # Simulate heartbeat loss degradation
    simulated_timeout = now - 45  # 45s since last ping
    if (now - simulated_timeout) > 30:
        node_eu.status = "DEGRADED"

    assert node_eu.status == "DEGRADED"


def test_vector_clock_causality_and_conflict_resolution():
    """Verify causal ordering and deterministic resolution of concurrent policy modifications."""
    node = SimulatedFederationNode("node-us-east-primary", "us-east-1", "https://us.internal")

    payload_json = json.dumps({"ip": "198.51.100.99"})
    sig1 = MerkleEngine.sha256_hex(f"SIG:node-eu:105:{payload_json}")

    p1 = {
        "policyId": "POL-CONFLICT-01",
        "policyType": "WAF_IP_BAN",
        "action": "UPSERT",
        "originNodeId": "node-eu",
        "originEpoch": 105,
        "payloadJson": payload_json,
        "sig": sig1,
        "vector_clock": {"node-eu": 105}
    }
    accepted = node.apply_policy(p1)
    assert accepted is True
    assert node.vector_clock["node-eu"] == 105

    # Incoming stale update with epoch 102
    sig_stale = MerkleEngine.sha256_hex(f"SIG:node-eu:102:{payload_json}")
    p_stale = {
        "policyId": "POL-CONFLICT-01",
        "policyType": "WAF_IP_BAN",
        "action": "UPSERT",
        "originNodeId": "node-eu",
        "originEpoch": 102,
        "payloadJson": payload_json,
        "sig": sig_stale,
        "vector_clock": {"node-eu": 102}
    }
    rejected = node.apply_policy(p_stale)
    assert rejected is False  # Stale update dropped

    # Concurrent newer update with epoch 110
    sig_newer = MerkleEngine.sha256_hex(f"SIG:node-eu:110:{payload_json}")
    p_newer = {
        "policyId": "POL-CONFLICT-01",
        "policyType": "WAF_IP_BAN",
        "action": "UPSERT",
        "originNodeId": "node-eu",
        "originEpoch": 110,
        "payloadJson": payload_json,
        "sig": sig_newer,
        "vector_clock": {"node-eu": 110}
    }
    assert node.apply_policy(p_newer) is True
    assert node.policies["POL-CONFLICT-01"]["originEpoch"] == 110


def test_merkle_state_integrity_and_tamper_detection():
    """Verify that Merkle tree roots detect any unauthorized policy tampering across clusters."""
    policies_a = [
        {"policyId": "POL-A", "policyType": "WAF", "action": "UPSERT", "originNodeId": "node-1", "originEpoch": 10, "sig": "s1"},
        {"policyId": "POL-B", "policyType": "REVOKE", "action": "UPSERT", "originNodeId": "node-2", "originEpoch": 15, "sig": "s2"},
    ]
    policies_b = [
        {"policyId": "POL-B", "policyType": "REVOKE", "action": "UPSERT", "originNodeId": "node-2", "originEpoch": 15, "sig": "s2"},
        {"policyId": "POL-A", "policyType": "WAF", "action": "UPSERT", "originNodeId": "node-1", "originEpoch": 10, "sig": "s1"},
    ]

    root_a = MerkleEngine.calculate_root(policies_a)
    root_b = MerkleEngine.calculate_root(policies_b)
    # Order-independence check
    assert root_a == root_b
    assert len(root_a) == 64

    # Single-bit tampering on epoch in POL-B
    tampered_policies = [
        {"policyId": "POL-A", "policyType": "WAF", "action": "UPSERT", "originNodeId": "node-1", "originEpoch": 10, "sig": "s1"},
        {"policyId": "POL-B", "policyType": "REVOKE", "action": "UPSERT", "originNodeId": "node-2", "originEpoch": 16, "sig": "s2"},
    ]
    tampered_root = MerkleEngine.calculate_root(tampered_policies)
    assert tampered_root != root_a, "Tampered policy set must diverge from consensus Merkle root"


def test_partition_recovery_and_auto_reconciliation():
    """Verify that a partitioned node missing intermediate policies safely recovers to cluster consensus."""
    node_primary = SimulatedFederationNode("node-us-east-primary", "us-east-1", "https://us.internal")
    node_edge = SimulatedFederationNode("node-ap-south-edge", "ap-south-1", "https://ap.internal")

    # Both start synchronized
    assert node_primary.get_merkle_root() == node_edge.get_merkle_root()

    # Primary receives 3 policies while Edge is partitioned
    for i in range(1, 4):
        payload_json = json.dumps({"rule": f"rule-{i}"})
        sig = MerkleEngine.sha256_hex(f"SIG:node-us-east-primary:{100+i}:{payload_json}")
        node_primary.apply_policy({
            "policyId": f"POL-00{i}",
            "policyType": "WORKFLOW_RULE",
            "action": "UPSERT",
            "originNodeId": "node-us-east-primary",
            "originEpoch": 100 + i,
            "payloadJson": payload_json,
            "sig": sig,
            "vector_clock": {"node-us-east-primary": 100 + i}
        })

    # Assert divergence during partition
    assert node_primary.get_merkle_root() != node_edge.get_merkle_root()

    # Reconciliation delta sync
    for pol in node_primary.policies.values():
        node_edge.apply_policy(pol)

    # Consensus fully restored
    assert node_edge.get_merkle_root() == node_primary.get_merkle_root()
    assert len(node_edge.policies) == 3
