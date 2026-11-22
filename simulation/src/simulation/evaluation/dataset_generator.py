"""Deterministic Scenario Dataset Generator for Research Evaluation Engine.

Generates 200 independently defined scenario executions across 4 ground-truth categories:
- 80 Benign
- 70 Malicious
- 30 Ambiguous
- 20 Incomplete Evidence

Enforces:
1. Strict ground-truth segregation: Ground truth persisted separately in ground_truth_v1_1.json.
2. Opaque, non-sequential scenario identifiers (scen-<hex>) randomized across categories.
3. Natural route and entity reuse: Benign and malicious scenarios share identical route templates.
4. Independent 4-way cryptographic hashing (telemetry, ground truth, scenario definitions, manifest).
5. Immutable preservation of historical DS-AEGIS-RESEARCH-V1 (v1.0.0).
"""

from __future__ import annotations

import datetime
import hashlib
import json
from pathlib import Path
import random
from typing import Any, Dict, List, Optional, Tuple

from simulation.evaluation.models import (
    DatasetManifest,
    EventTelemetry,
    GroundTruthArtifact,
    GroundTruthCategory,
    ScenarioDefinition,
    ScenarioGroundTruth,
    compute_canonical_ground_truth_hash,
    compute_canonical_scenario_definitions_hash,
    compute_canonical_telemetry_hash,
)

FORBIDDEN_LEAKED_TOKENS = [
    "benign",
    "malicious",
    "attack",
    "victim",
    "attacker",
    "harvest",
    "stealth",
    "internal-debug",
    "credentials",
    "directory",
    "ambiguous",
    "incomplete",
    "cust_drop",
    "cust_part",
    "cust_unk",
    "cust_amb",
    "cust_typo",
    "cust_sol",
    "stage2",
    "exfil",
]


class EvaluationDatasetGenerator:
    """Generates reproducible, statistically defensible 200-scenario evaluation datasets."""

    def __init__(self, master_seed: int = 42) -> None:
        self.master_seed = master_seed

    def generate_dataset(
        self,
        dataset_id: str = "DS-AEGIS-RESEARCH-V1.1",
        version: str = "1.1.0",
    ) -> Tuple[DatasetManifest, Dict[str, List[EventTelemetry]]]:
        """Backward-compatible generation router returning (manifest, telemetry_map)."""
        if version.startswith("1.0") or dataset_id == "DS-AEGIS-RESEARCH-V1":
            return self._generate_dataset_v1_legacy(dataset_id=dataset_id, version=version)
        manifest, _, telemetry_map = self.generate_dataset_v1_1(dataset_id=dataset_id, version=version)
        return manifest, telemetry_map

    # =========================================================================
    # VERSION 1.1: Opaque Interleaved IDs, Strict Separation, Realistic Routes
    # =========================================================================

    def generate_dataset_v1_1(
        self,
        dataset_id: str = "DS-AEGIS-RESEARCH-V1.1",
        version: str = "1.1.0",
    ) -> Tuple[DatasetManifest, GroundTruthArtifact, Dict[str, List[EventTelemetry]]]:
        """Generates 200 scenarios with opaque randomized IDs and separated ground truth."""
        rng = random.Random(self.master_seed)

        # Generate 200 deterministic opaque 8-character hex tokens
        # Format: scen-[0-9a-f]{8}
        opaque_tokens: List[str] = []
        for i in range(200):
            token_raw = hashlib.sha256(f"scen_id_v11:{self.master_seed}:{i}".encode("utf-8")).hexdigest()[:8]
            opaque_tokens.append(f"scen-{token_raw}")

        raw_scenarios: List[Tuple[ScenarioGroundTruth, List[EventTelemetry], ScenarioDefinition]] = []

        # 1. 80 BENIGN SCENARIOS
        for idx in range(1, 81):
            seed = rng.randint(100000, 999999)
            meta, events, sc_def = self._generate_benign_v1_1(idx, seed)
            raw_scenarios.append((meta, events, sc_def))

        # 2. 70 MALICIOUS SCENARIOS
        for idx in range(1, 71):
            seed = rng.randint(100000, 999999)
            meta, events, sc_def = self._generate_malicious_v1_1(idx, seed)
            raw_scenarios.append((meta, events, sc_def))

        # 3. 30 AMBIGUOUS SCENARIOS
        for idx in range(1, 31):
            seed = rng.randint(100000, 999999)
            meta, events, sc_def = self._generate_ambiguous_v1_1(idx, seed)
            raw_scenarios.append((meta, events, sc_def))

        # 4. 20 INCOMPLETE EVIDENCE SCENARIOS
        for idx in range(1, 21):
            seed = rng.randint(100000, 999999)
            meta, events, sc_def = self._generate_incomplete_v1_1(idx, seed)
            raw_scenarios.append((meta, events, sc_def))

        # Randomly shuffle scenario ordering independently of category
        rng.shuffle(raw_scenarios)

        # Assign opaque scenario IDs and update all event identifiers
        telemetry_map: Dict[str, List[EventTelemetry]] = {}
        ground_truth_scenarios: List[ScenarioGroundTruth] = []
        scenario_definitions: List[ScenarioDefinition] = []

        for i, (meta, events, sc_def) in enumerate(raw_scenarios):
            sc_id = opaque_tokens[i]

            # Update ground truth metadata
            meta.scenario_id = sc_id
            ground_truth_scenarios.append(meta)

            # Update structural definition
            sc_def.scenario_id = sc_id
            scenario_definitions.append(sc_def)

            # Update events
            assigned_events: List[EventTelemetry] = []
            for step, ev in enumerate(events):
                ev.scenario_id = sc_id
                ev.event_id = f"evt-{sc_id}-{step+1:02d}"
                ev.correlation_id = f"corr-{sc_id}-{step+1:02d}"
                assigned_events.append(ev)

            telemetry_map[sc_id] = assigned_events

        created_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # 1. Independent Telemetry Canonical Hash
        telemetry_hash = compute_canonical_telemetry_hash(telemetry_map)

        # 2. Independent Ground Truth Canonical Hash
        gt_hash = compute_canonical_ground_truth_hash(ground_truth_scenarios)

        # 3. Independent Scenario Definitions Canonical Hash
        sd_hash = compute_canonical_scenario_definitions_hash(scenario_definitions)

        # Build Ground Truth Artifact
        ground_truth_artifact = GroundTruthArtifact(
            dataset_id=dataset_id,
            version=version,
            created_at=created_timestamp,
            ground_truth_hash=gt_hash,
            total_scenarios=len(ground_truth_scenarios),
            population_distribution={
                "BENIGN": 80,
                "MALICIOUS": 70,
                "AMBIGUOUS": 30,
                "INCOMPLETE_EVIDENCE": 20,
            },
            scenarios=ground_truth_scenarios,
        )

        # Build Manifest (Contains NO ground-truth labels; structural definitions only)
        manifest = DatasetManifest(
            dataset_id=dataset_id,
            version=version,
            created_at=created_timestamp,
            telemetry_hash=telemetry_hash,
            ground_truth_hash=gt_hash,
            scenario_definitions_hash=sd_hash,
            total_scenarios=len(scenario_definitions),
            benign_count=80,
            malicious_count=70,
            ambiguous_count=30,
            incomplete_count=20,
            scenario_definitions=scenario_definitions,
        )
        # 4. Master Manifest Digest (binds metadata, counts, and sub-hashes)
        manifest.manifest_hash = manifest.calculate_manifest_hash()

        return manifest, ground_truth_artifact, telemetry_map

    # -------------------------------------------------------------------------
    # Realistic Scenarios (Shared routes, zero synthetic shortcuts)
    # -------------------------------------------------------------------------

    def _generate_benign_v1_1(
        self, index: int, seed: int
    ) -> Tuple[ScenarioGroundTruth, List[EventTelemetry], ScenarioDefinition]:
        cust_num = 1000 + index
        cust_id = f"cust_{cust_num}"
        user_id = f"usr_{cust_num}"
        tenant_id = f"tenant_{index % 5 + 1}"
        ip = "192.168.1.50" if index % 7 == 0 else f"10.0.{index // 256}.{index % 254 + 1}"
        events: List[EventTelemetry] = []

        sub_type = index % 8
        base_time = 1732180000000 + (index * 60000)

        if sub_type == 0:
            name = f"Benign Customer Profile & Account Check #{index}"
            endpoints = [
                ("GET", f"/api/v1/customers/{cust_id}", "/api/v1/customers/{id}", 200, cust_id, "CONFIDENTIAL", ["id", "name", "email"]),
                ("GET", f"/api/v1/accounts?customerId={cust_id}", "/api/v1/accounts", 200, cust_id, "CONFIDENTIAL", ["accountId", "balance"]),
                ("GET", f"/api/v1/accounts/acc_{cust_num}/balance", "/api/v1/accounts/{id}/balance", 200, cust_id, "CONFIDENTIAL", ["balance", "currency"]),
                ("GET", f"/api/v1/transactions?accountId=acc_{cust_num}", "/api/v1/transactions", 200, cust_id, "CONFIDENTIAL", ["transactionId", "amount"]),
            ]
            for step, (m, u, r, s, o, sens, fields) in enumerate(endpoints):
                events.append(
                    EventTelemetry(
                        event_id="",
                        scenario_id="",
                        timestamp_epoch_ms=base_time + (step * 500),
                        http_method=m,
                        url=u,
                        normalized_route=r,
                        status_code=s,
                        user_id=user_id,
                        auth_subject=user_id,
                        tenant_id=tenant_id,
                        source_ip=ip,
                        customer_id=cust_id,
                        resource_owner_id=o,
                        sensitivity=sens,
                        observed_fields=fields,
                        response_bytes=420,
                        correlation_id="",
                    )
                )

        elif sub_type == 1:
            name = f"Benign Repeated Reads Own Account #{index}"
            for step in range(6):
                events.append(
                    EventTelemetry(
                        event_id="",
                        scenario_id="",
                        timestamp_epoch_ms=base_time + (step * 1000),
                        http_method="GET",
                        url=f"/api/v1/accounts/acc_{cust_num}/balance",
                        normalized_route="/api/v1/accounts/{id}/balance",
                        status_code=200,
                        user_id=user_id,
                        auth_subject=user_id,
                        tenant_id=tenant_id,
                        source_ip=ip,
                        customer_id=cust_id,
                        resource_owner_id=cust_id,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["balance", "currency"],
                        response_bytes=180,
                        correlation_id="",
                    )
                )

        elif sub_type == 2:
            name = f"Benign Transaction Pagination #{index}"
            for page in range(1, 4):
                events.append(
                    EventTelemetry(
                        event_id="",
                        scenario_id="",
                        timestamp_epoch_ms=base_time + ((page - 1) * 3000),
                        http_method="GET",
                        url=f"/api/v1/transactions?accountId=acc_{cust_num}&page={page}&size=10",
                        normalized_route="/api/v1/transactions",
                        status_code=200,
                        user_id=user_id,
                        auth_subject=user_id,
                        tenant_id=tenant_id,
                        source_ip=ip,
                        customer_id=cust_id,
                        resource_owner_id=cust_id,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["items", "page", "totalPages"],
                        page_number=page,
                        page_size=10,
                        response_bytes=1200,
                        correlation_id="",
                    )
                )

        elif sub_type == 3:
            name = f"Benign Shared Corporate NAT Session #{index}"
            for step in range(4):
                e_user = f"usr_{cust_num}_{step}"
                e_cust = f"cust_{cust_num}_{step}"
                events.append(
                    EventTelemetry(
                        event_id="",
                        scenario_id="",
                        timestamp_epoch_ms=base_time + (step * 400),
                        http_method="GET",
                        url=f"/api/v1/customers/{e_cust}",
                        normalized_route="/api/v1/customers/{id}",
                        status_code=200,
                        user_id=e_user,
                        auth_subject=e_user,
                        tenant_id=tenant_id,
                        source_ip="203.0.113.50",
                        customer_id=e_cust,
                        resource_owner_id=e_cust,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["id", "name"],
                        response_bytes=350,
                        correlation_id="",
                    )
                )

        elif sub_type == 4:
            name = f"Benign Administrative Setting Denial #{index}"
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url="/api/v1/system/settings",
                    normalized_route="/api/v1/system/settings",
                    status_code=403,
                    user_id=user_id,
                    auth_subject=user_id,
                    tenant_id=tenant_id,
                    source_ip=ip,
                    customer_id=cust_id,
                    resource_owner_id=None,
                    sensitivity="INTERNAL",
                    observed_fields=["error", "message"],
                    response_bytes=120,
                    correlation_id="",
                )
            )
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time + 1000,
                    http_method="GET",
                    url=f"/api/v1/customers/{cust_id}",
                    normalized_route="/api/v1/customers/{id}",
                    status_code=200,
                    user_id=user_id,
                    auth_subject=user_id,
                    tenant_id=tenant_id,
                    source_ip=ip,
                    customer_id=cust_id,
                    resource_owner_id=cust_id,
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["id", "name"],
                    response_bytes=350,
                    correlation_id="",
                )
            )

        elif sub_type == 5:
            name = f"Benign Multi-Account Access Same Customer #{index}"
            for step, acc_id in enumerate([f"acc_a_{cust_num}", f"acc_b_{cust_num}", f"acc_c_{cust_num}"]):
                events.append(
                    EventTelemetry(
                        event_id="",
                        scenario_id="",
                        timestamp_epoch_ms=base_time + (step * 800),
                        http_method="GET",
                        url=f"/api/v1/accounts/{acc_id}",
                        normalized_route="/api/v1/accounts/{id}",
                        status_code=200,
                        user_id=user_id,
                        auth_subject=user_id,
                        tenant_id=tenant_id,
                        source_ip=ip,
                        customer_id=cust_id,
                        resource_owner_id=cust_id,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["id", "balance", "type"],
                        response_bytes=400,
                        correlation_id="",
                    )
                )

        elif sub_type == 6:
            name = f"Benign Legitimate Transfer Workflow #{index}"
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/accounts/acc_{cust_num}/balance",
                    normalized_route="/api/v1/accounts/{id}/balance",
                    status_code=200,
                    user_id=user_id,
                    auth_subject=user_id,
                    tenant_id=tenant_id,
                    source_ip=ip,
                    customer_id=cust_id,
                    resource_owner_id=cust_id,
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["balance"],
                    response_bytes=150,
                    correlation_id="",
                )
            )
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time + 1500,
                    http_method="POST",
                    url="/api/v1/transactions/transfers",
                    normalized_route="/api/v1/transactions/transfers",
                    status_code=201,
                    user_id=user_id,
                    auth_subject=user_id,
                    tenant_id=tenant_id,
                    source_ip=ip,
                    customer_id=cust_id,
                    resource_owner_id=cust_id,
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["transactionId", "status", "amount"],
                    response_bytes=220,
                    correlation_id="",
                )
            )
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time + 3000,
                    http_method="GET",
                    url=f"/api/v1/accounts/acc_{cust_num}/balance",
                    normalized_route="/api/v1/accounts/{id}/balance",
                    status_code=200,
                    user_id=user_id,
                    auth_subject=user_id,
                    tenant_id=tenant_id,
                    source_ip=ip,
                    customer_id=cust_id,
                    resource_owner_id=cust_id,
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["balance"],
                    response_bytes=150,
                    correlation_id="",
                )
            )

        else:
            name = f"Benign Dashboard Refresh Sequence #{index}"
            for step in range(5):
                events.append(
                    EventTelemetry(
                        event_id="",
                        scenario_id="",
                        timestamp_epoch_ms=base_time + (step * 250),
                        http_method="GET",
                        url=f"/api/v1/customers/{cust_id}/summary",
                        normalized_route="/api/v1/customers/{id}/summary",
                        status_code=200,
                        user_id=user_id,
                        auth_subject=user_id,
                        tenant_id=tenant_id,
                        source_ip=ip,
                        customer_id=cust_id,
                        resource_owner_id=cust_id,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["accounts", "totalBalance"],
                        response_bytes=850,
                        correlation_id="",
                    )
                )

        duration = round((events[-1].timestamp_epoch_ms - events[0].timestamp_epoch_ms) / 1000.0, 2)
        meta = ScenarioGroundTruth(
            scenario_id="",
            scenario_family="BENIGN_OPERATIONS",
            scenario_name=name,
            category=GroundTruthCategory.BENIGN,
            expected_detection=False,
            expected_campaign=False,
            expected_rules=[],
            seed=seed,
            num_requests=len(events),
            num_identities=1 if sub_type != 3 else 4,
            num_tenants=1,
            num_resources=len(set(e.url for e in events)),
            duration_seconds=duration,
            description="Authorized clean benign banking operations.",
        )
        sc_def = ScenarioDefinition(
            scenario_id="",
            seed=seed,
            num_requests=len(events),
            num_identities=1 if sub_type != 3 else 4,
            num_tenants=1,
            num_resources=len(set(e.url for e in events)),
            duration_seconds=duration,
        )
        return meta, events, sc_def

    def _generate_malicious_v1_1(
        self, index: int, seed: int
    ) -> Tuple[ScenarioGroundTruth, List[EventTelemetry], ScenarioDefinition]:
        attacker_num = 5000 + index
        attacker_cust = f"cust_{attacker_num}"
        attacker_user = f"usr_{attacker_num}"
        attacker_tenant = f"tenant_{index % 3 + 1}"
        ip = f"198.51.100.{index % 250 + 1}"
        events: List[EventTelemetry] = []

        sub_type = index % 7
        base_time = 1732185000000 + (index * 60000)

        if sub_type == 0:
            # Confirmed BOLA Data Leak: querying standard /api/v1/customers/{id} route, but cross-owner
            name = f"Confirmed Cross-Tenant BOLA Data Leak #{index}"
            victim_cust = f"cust_{2000 + (index * 10)}"
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/customers/{victim_cust}",
                    normalized_route="/api/v1/customers/{id}",
                    status_code=200,
                    user_id=attacker_user,
                    auth_subject=attacker_user,
                    tenant_id=attacker_tenant,
                    source_ip=ip,
                    customer_id=attacker_cust,
                    resource_owner_id=victim_cust,
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["id", "name", "email", "phone", "ssn"],
                    response_bytes=680,
                    correlation_id="",
                )
            )
            expected_rules = ["RULE-BOLA-CONFIRMED-01"]
            exp_camp = False

        elif sub_type == 1:
            # BOLA Account Enumeration: querying standard /api/v1/accounts/{id} route
            name = f"BOLA Account Enumeration Campaign #{index}"
            expected_rules = ["RULE-BOLA-01", "RULE-BOLA-02"]
            exp_camp = False
            for step in range(4):
                victim_acc = f"acc_{6000 + index}_{step}"
                events.append(
                    EventTelemetry(
                        event_id="",
                        scenario_id="",
                        timestamp_epoch_ms=base_time + (step * 800),
                        http_method="GET",
                        url=f"/api/v1/accounts/{victim_acc}",
                        normalized_route="/api/v1/accounts/{id}",
                        status_code=403,
                        user_id=attacker_user,
                        auth_subject=attacker_user,
                        tenant_id=attacker_tenant,
                        source_ip=ip,
                        customer_id=attacker_cust,
                        resource_owner_id=f"cust_{7000 + step}",
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["error"],
                        response_bytes=130,
                        correlation_id="",
                    )
                )

        elif sub_type == 2:
            # Rapid Burst Customer Harvesting: standard /api/v1/customers/{id} across multiple IDs in <5s
            name = f"Rapid Burst Customer Harvesting #{index}"
            expected_rules = ["RULE-BULK-EXTRACT-01"]
            exp_camp = False
            for step in range(4):
                victim_cust = f"cust_{3000 + (index * 10) + step}"
                events.append(
                    EventTelemetry(
                        event_id="",
                        scenario_id="",
                        timestamp_epoch_ms=base_time + (step * 1200),
                        http_method="GET",
                        url=f"/api/v1/customers/{victim_cust}",
                        normalized_route="/api/v1/customers/{id}",
                        status_code=200,
                        user_id=attacker_user,
                        auth_subject=attacker_user,
                        tenant_id=attacker_tenant,
                        source_ip=ip,
                        customer_id=attacker_cust,
                        resource_owner_id=victim_cust,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["id", "name", "balance"],
                        response_bytes=520,
                        correlation_id="",
                    )
                )

        elif sub_type == 3:
            # Low-and-Slow Stealth Extraction: standard /api/v1/customers/{id} spaced 75s apart
            name = f"Low-and-Slow Stealth Extraction #{index}"
            expected_rules = ["RULE-ADV-EXTRACT-01"]
            exp_camp = False
            for step in range(5):
                victim_cust = f"cust_{4000 + (index * 10) + step}"
                events.append(
                    EventTelemetry(
                        event_id="",
                        scenario_id="",
                        timestamp_epoch_ms=base_time + (step * 75000),
                        http_method="GET",
                        url=f"/api/v1/customers/{victim_cust}",
                        normalized_route="/api/v1/customers/{id}",
                        status_code=200,
                        user_id=attacker_user,
                        auth_subject=attacker_user,
                        tenant_id=attacker_tenant,
                        source_ip=ip,
                        customer_id=attacker_cust,
                        resource_owner_id=victim_cust,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["id", "name"],
                        response_bytes=410,
                        correlation_id="",
                    )
                )

        elif sub_type == 4:
            # Excessive Data Exposure: standard /api/v1/customers/{id} returning RESTRICTED payload fields
            name = f"Excessive Secret Data Exposure #{index}"
            expected_rules = ["RULE-EXCESSIVE-EXPOSURE-01"]
            exp_camp = False
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/customers/{attacker_cust}",
                    normalized_route="/api/v1/customers/{id}",
                    status_code=200,
                    user_id=attacker_user,
                    auth_subject=attacker_user,
                    tenant_id=attacker_tenant,
                    source_ip=ip,
                    customer_id=attacker_cust,
                    resource_owner_id=attacker_cust,
                    sensitivity="RESTRICTED",
                    observed_fields=["id", "auth_token_hash", "temporary_cleartext_secret", "master_key"],
                    response_bytes=890,
                    correlation_id="",
                )
            )

        elif sub_type == 5:
            # Automated Pagination Harvesting: standard /api/v1/transactions with size=50 and high bytes
            name = f"Automated Sensitive Pagination Harvesting #{index}"
            expected_rules = ["RULE-ADV-EXTRACT-01"]
            exp_camp = False
            for p in range(1, 5):
                events.append(
                    EventTelemetry(
                        event_id="",
                        scenario_id="",
                        timestamp_epoch_ms=base_time + ((p - 1) * 600),
                        http_method="GET",
                        url=f"/api/v1/transactions?accountId=acc_{attacker_num}&page={p}&size=50",
                        normalized_route="/api/v1/transactions",
                        status_code=200,
                        user_id=attacker_user,
                        auth_subject=attacker_user,
                        tenant_id=attacker_tenant,
                        source_ip=ip,
                        customer_id=attacker_cust,
                        resource_owner_id=None,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["records", "page", "size"],
                        page_number=p,
                        page_size=50,
                        response_bytes=15000,
                        correlation_id="",
                    )
                )

        else:
            # Multi-Stage Exfiltration Campaign
            name = f"Multi-Stage Exfiltration Intrusion Campaign #{index}"
            expected_rules = ["RULE-PROBE-01", "RULE-BOLA-01", "RULE-BULK-EXTRACT-01", "DATA_EXFILTRATION_CAMPAIGN"]
            exp_camp = True
            # Stage 1: Recon (404 on actuator)
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url="/actuator/env",
                    normalized_route="/actuator/env",
                    status_code=404,
                    user_id=attacker_user,
                    auth_subject=attacker_user,
                    tenant_id=attacker_tenant,
                    source_ip=ip,
                    customer_id=attacker_cust,
                    resource_owner_id=None,
                    sensitivity="UNKNOWN",
                    observed_fields=["error"],
                    response_bytes=90,
                    correlation_id="",
                )
            )
            # Stage 2: Authorization Probing (403 on accounts route)
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time + 5000,
                    http_method="GET",
                    url=f"/api/v1/accounts/acc_{8000 + index}",
                    normalized_route="/api/v1/accounts/{id}",
                    status_code=403,
                    user_id=attacker_user,
                    auth_subject=attacker_user,
                    tenant_id=attacker_tenant,
                    source_ip=ip,
                    customer_id=attacker_cust,
                    resource_owner_id=f"cust_{8000 + index}",
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["error"],
                    response_bytes=130,
                    correlation_id="",
                )
            )
            # Stage 3: Extraction (3 rapid reads on customers route)
            for step in range(3):
                target_cust = f"cust_{8500 + (index * 10) + step}"
                events.append(
                    EventTelemetry(
                        event_id="",
                        scenario_id="",
                        timestamp_epoch_ms=base_time + 12000 + (step * 1000),
                        http_method="GET",
                        url=f"/api/v1/customers/{target_cust}",
                        normalized_route="/api/v1/customers/{id}",
                        status_code=200,
                        user_id=attacker_user,
                        auth_subject=attacker_user,
                        tenant_id=attacker_tenant,
                        source_ip=ip,
                        customer_id=attacker_cust,
                        resource_owner_id=target_cust,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["id", "name", "balance"],
                        response_bytes=600,
                        correlation_id="",
                    )
                )

        duration = round((events[-1].timestamp_epoch_ms - events[0].timestamp_epoch_ms) / 1000.0, 2)
        meta = ScenarioGroundTruth(
            scenario_id="",
            scenario_family="ATTACK_CAMPAIGNS",
            scenario_name=name,
            category=GroundTruthCategory.MALICIOUS,
            expected_detection=True,
            expected_campaign=exp_camp,
            expected_rules=expected_rules,
            seed=seed,
            num_requests=len(events),
            num_identities=1,
            num_tenants=2 if sub_type == 0 else 1,
            num_resources=len(set(e.url for e in events)),
            duration_seconds=duration,
            description="Active unauthorized security intrusion or exfiltration attempt.",
        )
        sc_def = ScenarioDefinition(
            scenario_id="",
            seed=seed,
            num_requests=len(events),
            num_identities=1,
            num_tenants=2 if sub_type == 0 else 1,
            num_resources=len(set(e.url for e in events)),
            duration_seconds=duration,
        )
        return meta, events, sc_def

    def _generate_ambiguous_v1_1(
        self, index: int, seed: int
    ) -> Tuple[ScenarioGroundTruth, List[EventTelemetry], ScenarioDefinition]:
        events: List[EventTelemetry] = []
        base_time = 1732190000000 + (index * 60000)
        sub_type = index % 5

        if sub_type == 0:
            name = f"Ambiguous Missing Ownership Context #{index}"
            u_id = f"usr_{9000 + index}"
            c_id = f"cust_{9000 + index}"
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/legacy/records/{index}",
                    normalized_route="/api/v1/legacy/records/{id}",
                    status_code=200,
                    user_id=u_id,
                    auth_subject=u_id,
                    tenant_id=f"tenant_{index % 3 + 1}",
                    source_ip="10.0.4.1",
                    customer_id=c_id,
                    resource_owner_id=None,
                    sensitivity="UNKNOWN",
                    observed_fields=["record_id", "data"],
                    response_bytes=300,
                    correlation_id="",
                )
            )

        elif sub_type == 1:
            name = f"Ambiguous Missing Tenant Header #{index}"
            u_id = f"usr_{9100 + index}"
            c_id = f"cust_{9100 + index}"
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/customers/{c_id}",
                    normalized_route="/api/v1/customers/{id}",
                    status_code=200,
                    user_id=u_id,
                    auth_subject=u_id,
                    tenant_id=None,
                    source_ip="172.16.0.22",
                    customer_id=c_id,
                    resource_owner_id=c_id,
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["id", "name"],
                    response_bytes=350,
                    correlation_id="",
                )
            )

        elif sub_type == 2:
            name = f"Ambiguous Schema Drift Unclassified Endpoint #{index}"
            u_id = f"usr_{9200 + index}"
            c_id = f"cust_{9200 + index}"
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/preview/features/{index}",
                    normalized_route="/api/v1/preview/features/{id}",
                    status_code=200,
                    user_id=u_id,
                    auth_subject=u_id,
                    tenant_id="tenant_1",
                    source_ip="10.10.1.5",
                    customer_id=c_id,
                    resource_owner_id=c_id,
                    sensitivity="UNKNOWN",
                    observed_fields=["featureFlag", "rawMetadata"],
                    response_bytes=510,
                    correlation_id="",
                )
            )

        elif sub_type == 3:
            name = f"Ambiguous Misspelled Route 404 #{index}"
            u_id = f"usr_{9300 + index}"
            c_id = f"cust_{9300 + index}"
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url="/api/v1/custmers/profile",
                    normalized_route="/api/v1/custmers/profile",
                    status_code=404,
                    user_id=u_id,
                    auth_subject=u_id,
                    tenant_id="tenant_1",
                    source_ip="192.168.1.99",
                    customer_id=c_id,
                    resource_owner_id=None,
                    sensitivity="UNKNOWN",
                    observed_fields=["error"],
                    response_bytes=110,
                    correlation_id="",
                )
            )

        else:
            name = f"Ambiguous Solitary 403 Access Attempt #{index}"
            u_id = f"usr_{9400 + index}"
            c_id = f"cust_{9400 + index}"
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/accounts/acc_{9400 + index}",
                    normalized_route="/api/v1/accounts/{id}",
                    status_code=403,
                    user_id=u_id,
                    auth_subject=u_id,
                    tenant_id="tenant_2",
                    source_ip="10.2.2.1",
                    customer_id=c_id,
                    resource_owner_id=f"cust_{9450 + index}",
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["error"],
                    response_bytes=130,
                    correlation_id="",
                )
            )

        duration = round((events[-1].timestamp_epoch_ms - events[0].timestamp_epoch_ms) / 1000.0, 2)
        meta = ScenarioGroundTruth(
            scenario_id="",
            scenario_family="AMBIGUOUS_CONDITIONS",
            scenario_name=name,
            category=GroundTruthCategory.AMBIGUOUS,
            expected_detection=False,
            expected_campaign=False,
            expected_rules=[],
            seed=seed,
            num_requests=len(events),
            num_identities=1,
            num_tenants=1,
            num_resources=len(set(e.url for e in events)),
            duration_seconds=duration,
            description="Ambiguous operational telemetry with incomplete context requiring uncertainty handling.",
        )
        sc_def = ScenarioDefinition(
            scenario_id="",
            seed=seed,
            num_requests=len(events),
            num_identities=1,
            num_tenants=1,
            num_resources=len(set(e.url for e in events)),
            duration_seconds=duration,
        )
        return meta, events, sc_def

    def _generate_incomplete_v1_1(
        self, index: int, seed: int
    ) -> Tuple[ScenarioGroundTruth, List[EventTelemetry], ScenarioDefinition]:
        events: List[EventTelemetry] = []
        base_time = 1732195000000 + (index * 60000)
        sub_type = index % 4

        if sub_type == 0:
            name = f"Incomplete Evidence Dropped Payload Body #{index}"
            u_id = f"usr_{9500 + index}"
            c_id = f"cust_{9500 + index}"
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/customers/{c_id}",
                    normalized_route="/api/v1/customers/{id}",
                    status_code=200,
                    user_id=u_id,
                    auth_subject=u_id,
                    tenant_id="tenant_1",
                    source_ip="10.8.0.1",
                    customer_id=c_id,
                    resource_owner_id=c_id,
                    sensitivity="CONFIDENTIAL",
                    observed_fields=[],
                    response_bytes=0,
                    correlation_id="",
                )
            )

        elif sub_type == 1:
            name = f"Incomplete Interrupted Campaign Recon Only #{index}"
            u_id = f"usr_{9600 + index}"
            c_id = f"cust_{9600 + index}"
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url="/actuator/health",
                    normalized_route="/actuator/health",
                    status_code=404,
                    user_id=u_id,
                    auth_subject=u_id,
                    tenant_id="tenant_1",
                    source_ip="198.51.100.77",
                    customer_id=c_id,
                    resource_owner_id=None,
                    sensitivity="UNKNOWN",
                    observed_fields=["status"],
                    response_bytes=80,
                    correlation_id="",
                )
            )

        elif sub_type == 2:
            name = f"Incomplete Unspecified Service Contract #{index}"
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time,
                    http_method="POST",
                    url="/api/v1/external/third-party/webhook",
                    normalized_route="/api/v1/external/third-party/webhook",
                    status_code=202,
                    user_id=None,
                    auth_subject=None,
                    tenant_id=None,
                    source_ip="203.0.113.190",
                    customer_id=None,
                    resource_owner_id=None,
                    sensitivity="UNKNOWN",
                    observed_fields=["payloadId", "hookTimestamp"],
                    response_bytes=140,
                    correlation_id="",
                )
            )

        else:
            name = f"Incomplete Partial Multi-Domain Sequence #{index}"
            u_id = f"usr_{9700 + index}"
            c_id = f"cust_{9700 + index}"
            events.append(
                EventTelemetry(
                    event_id="",
                    scenario_id="",
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/customers/{c_id}",
                    normalized_route="/api/v1/customers/{id}",
                    status_code=200,
                    user_id=u_id,
                    auth_subject=u_id,
                    tenant_id="tenant_3",
                    source_ip="198.51.100.99",
                    customer_id=c_id,
                    resource_owner_id=c_id,
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["id", "balance"],
                    response_bytes=380,
                    correlation_id="",
                )
            )

        duration = round((events[-1].timestamp_epoch_ms - events[0].timestamp_epoch_ms) / 1000.0, 2)
        meta = ScenarioGroundTruth(
            scenario_id="",
            scenario_family="INCOMPLETE_EVIDENCE",
            scenario_name=name,
            category=GroundTruthCategory.INCOMPLETE_EVIDENCE,
            expected_detection=False,
            expected_campaign=False,
            expected_rules=[],
            seed=seed,
            num_requests=len(events),
            num_identities=1,
            num_tenants=1,
            num_resources=len(set(e.url for e in events)),
            duration_seconds=duration,
            description="Incomplete telemetry or interrupted sequence requiring uncertainty handling.",
        )
        sc_def = ScenarioDefinition(
            scenario_id="",
            seed=seed,
            num_requests=len(events),
            num_identities=1,
            num_tenants=1,
            num_resources=len(set(e.url for e in events)),
            duration_seconds=duration,
        )
        return meta, events, sc_def

    # =========================================================================
    # VERSION 1.0 (LEGACY): Preserved exactly for backward compatibility
    # =========================================================================

    def _generate_dataset_v1_legacy(
        self,
        dataset_id: str = "DS-AEGIS-RESEARCH-V1",
        version: str = "1.0.0",
    ) -> Tuple[DatasetManifest, Dict[str, List[EventTelemetry]]]:
        scenarios: List[ScenarioGroundTruth] = []
        telemetry_map: Dict[str, List[EventTelemetry]] = {}
        rng = random.Random(self.master_seed)

        for idx in range(1, 81):
            sc_id = f"EVAL-BENIGN-{idx:03d}"
            seed = rng.randint(100000, 999999)
            meta, events = self._generate_benign_legacy(sc_id, idx, seed)
            scenarios.append(meta)
            telemetry_map[sc_id] = events

        for idx in range(1, 71):
            sc_id = f"EVAL-MALICIOUS-{idx:03d}"
            seed = rng.randint(100000, 999999)
            meta, events = self._generate_malicious_legacy(sc_id, idx, seed)
            scenarios.append(meta)
            telemetry_map[sc_id] = events

        for idx in range(1, 31):
            sc_id = f"EVAL-AMBIGUOUS-{idx:03d}"
            seed = rng.randint(100000, 999999)
            meta, events = self._generate_ambiguous_legacy(sc_id, idx, seed)
            scenarios.append(meta)
            telemetry_map[sc_id] = events

        for idx in range(1, 21):
            sc_id = f"EVAL-INCOMPLETE-{idx:03d}"
            seed = rng.randint(100000, 999999)
            meta, events = self._generate_incomplete_legacy(sc_id, idx, seed)
            scenarios.append(meta)
            telemetry_map[sc_id] = events

        manifest = DatasetManifest(
            dataset_id=dataset_id,
            version=version,
            created_at="2026-11-21T13:15:44.022778+00:00",
            total_scenarios=len(scenarios),
            benign_count=80,
            malicious_count=70,
            ambiguous_count=30,
            incomplete_count=20,
            scenarios=scenarios,
        )
        manifest.manifest_hash = manifest.calculate_hash()
        return manifest, telemetry_map

    def _generate_benign_legacy(
        self, sc_id: str, index: int, seed: int
    ) -> Tuple[ScenarioGroundTruth, List[EventTelemetry]]:
        cust_num = 1000 + index
        cust_id = f"cust_{cust_num}"
        user_id = f"user_{cust_num}"
        tenant_id = f"tenant_{index % 5 + 1}"
        ip = "192.168.1.50" if index % 7 == 0 else f"10.0.{index // 256}.{index % 254 + 1}"
        events: List[EventTelemetry] = []
        sub_type = index % 8
        base_time = 1732180000000 + (index * 60000)

        if sub_type == 0:
            name = f"Benign Customer Profile & Account Check #{index}"
            endpoints = [
                ("GET", f"/api/v1/customers/{cust_id}", 200, cust_id, "CONFIDENTIAL", ["id", "name", "email"]),
                ("GET", f"/api/v1/accounts?customerId={cust_id}", 200, cust_id, "CONFIDENTIAL", ["accountId", "balance"]),
                ("GET", f"/api/v1/accounts/acc_{cust_num}/balance", 200, cust_id, "CONFIDENTIAL", ["balance", "currency"]),
                ("GET", f"/api/v1/transactions?accountId=acc_{cust_num}", 200, cust_id, "CONFIDENTIAL", ["transactionId", "amount"]),
            ]
            for step, (m, u, s, o, sens, fields) in enumerate(endpoints):
                events.append(
                    EventTelemetry(
                        event_id=f"evt-{sc_id}-{step+1}",
                        scenario_id=sc_id,
                        timestamp_epoch_ms=base_time + (step * 500),
                        http_method=m,
                        url=u,
                        normalized_route="/api/v1/customers/{id}" if "customers" in u else "/api/v1/accounts",
                        status_code=s,
                        user_id=user_id,
                        auth_subject=user_id,
                        tenant_id=tenant_id,
                        source_ip=ip,
                        customer_id=cust_id,
                        resource_owner_id=o,
                        sensitivity=sens,
                        observed_fields=fields,
                        response_bytes=420,
                        correlation_id=f"corr-{sc_id}-{step+1}",
                    )
                )
        elif sub_type == 1:
            name = f"Benign Repeated Reads Own Account #{index}"
            for step in range(6):
                events.append(
                    EventTelemetry(
                        event_id=f"evt-{sc_id}-{step+1}",
                        scenario_id=sc_id,
                        timestamp_epoch_ms=base_time + (step * 1000),
                        http_method="GET",
                        url=f"/api/v1/accounts/acc_{cust_num}/balance",
                        normalized_route="/api/v1/accounts/{id}/balance",
                        status_code=200,
                        user_id=user_id,
                        auth_subject=user_id,
                        tenant_id=tenant_id,
                        source_ip=ip,
                        customer_id=cust_id,
                        resource_owner_id=cust_id,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["balance", "currency"],
                        response_bytes=180,
                        correlation_id=f"corr-{sc_id}-{step+1}",
                    )
                )
        elif sub_type == 2:
            name = f"Benign Transaction Pagination #{index}"
            for page in range(1, 4):
                events.append(
                    EventTelemetry(
                        event_id=f"evt-{sc_id}-{page}",
                        scenario_id=sc_id,
                        timestamp_epoch_ms=base_time + ((page - 1) * 3000),
                        http_method="GET",
                        url=f"/api/v1/transactions?accountId=acc_{cust_num}&page={page}&size=10",
                        normalized_route="/api/v1/transactions",
                        status_code=200,
                        user_id=user_id,
                        auth_subject=user_id,
                        tenant_id=tenant_id,
                        source_ip=ip,
                        customer_id=cust_id,
                        resource_owner_id=cust_id,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["items", "page", "totalPages"],
                        page_number=page,
                        page_size=10,
                        response_bytes=1200,
                        correlation_id=f"corr-{sc_id}-{page}",
                    )
                )
        elif sub_type == 3:
            name = f"Benign Shared Corporate NAT Session #{index}"
            for step in range(4):
                e_user = f"nat_user_{cust_num}_{step}"
                events.append(
                    EventTelemetry(
                        event_id=f"evt-{sc_id}-{step+1}",
                        scenario_id=sc_id,
                        timestamp_epoch_ms=base_time + (step * 400),
                        http_method="GET",
                        url=f"/api/v1/customers/cust_nat_{cust_num}_{step}",
                        normalized_route="/api/v1/customers/{id}",
                        status_code=200,
                        user_id=e_user,
                        auth_subject=e_user,
                        tenant_id=tenant_id,
                        source_ip="203.0.113.50",
                        customer_id=f"cust_nat_{cust_num}_{step}",
                        resource_owner_id=f"cust_nat_{cust_num}_{step}",
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["id", "name"],
                        response_bytes=350,
                        correlation_id=f"corr-{sc_id}-{step+1}",
                    )
                )
        elif sub_type == 4:
            name = f"Benign Legitimate Administrative Role Denial #{index}"
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-1",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url="/api/v1/security/overview",
                    normalized_route="/api/v1/security/overview",
                    status_code=403,
                    user_id=user_id,
                    auth_subject=user_id,
                    tenant_id=tenant_id,
                    source_ip=ip,
                    customer_id=cust_id,
                    resource_owner_id=None,
                    sensitivity="INTERNAL",
                    observed_fields=["error", "message"],
                    response_bytes=120,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-2",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time + 1000,
                    http_method="GET",
                    url=f"/api/v1/customers/{cust_id}",
                    normalized_route="/api/v1/customers/{id}",
                    status_code=200,
                    user_id=user_id,
                    auth_subject=user_id,
                    tenant_id=tenant_id,
                    source_ip=ip,
                    customer_id=cust_id,
                    resource_owner_id=cust_id,
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["id", "name"],
                    response_bytes=350,
                    correlation_id=f"corr-{sc_id}-2",
                )
            )
        elif sub_type == 5:
            name = f"Benign Multi-Account Access Same Customer #{index}"
            for step, acc_id in enumerate([f"acc_a_{cust_num}", f"acc_b_{cust_num}", f"acc_c_{cust_num}"]):
                events.append(
                    EventTelemetry(
                        event_id=f"evt-{sc_id}-{step+1}",
                        scenario_id=sc_id,
                        timestamp_epoch_ms=base_time + (step * 800),
                        http_method="GET",
                        url=f"/api/v1/accounts/{acc_id}",
                        normalized_route="/api/v1/accounts/{id}",
                        status_code=200,
                        user_id=user_id,
                        auth_subject=user_id,
                        tenant_id=tenant_id,
                        source_ip=ip,
                        customer_id=cust_id,
                        resource_owner_id=cust_id,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["id", "balance", "type"],
                        response_bytes=400,
                        correlation_id=f"corr-{sc_id}-{step+1}",
                    )
                )
        elif sub_type == 6:
            name = f"Benign Legitimate Transfer Workflow #{index}"
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-1",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/accounts/acc_{cust_num}/balance",
                    normalized_route="/api/v1/accounts/{id}/balance",
                    status_code=200,
                    user_id=user_id,
                    auth_subject=user_id,
                    tenant_id=tenant_id,
                    source_ip=ip,
                    customer_id=cust_id,
                    resource_owner_id=cust_id,
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["balance"],
                    response_bytes=150,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-2",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time + 1500,
                    http_method="POST",
                    url="/api/v1/transactions/transfers",
                    normalized_route="/api/v1/transactions/transfers",
                    status_code=201,
                    user_id=user_id,
                    auth_subject=user_id,
                    tenant_id=tenant_id,
                    source_ip=ip,
                    customer_id=cust_id,
                    resource_owner_id=cust_id,
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["transactionId", "status", "amount"],
                    response_bytes=220,
                    correlation_id=f"corr-{sc_id}-2",
                )
            )
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-3",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time + 3000,
                    http_method="GET",
                    url=f"/api/v1/accounts/acc_{cust_num}/balance",
                    normalized_route="/api/v1/accounts/{id}/balance",
                    status_code=200,
                    user_id=user_id,
                    auth_subject=user_id,
                    tenant_id=tenant_id,
                    source_ip=ip,
                    customer_id=cust_id,
                    resource_owner_id=cust_id,
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["balance"],
                    response_bytes=150,
                    correlation_id=f"corr-{sc_id}-3",
                )
            )
        else:
            name = f"Benign Dashboard Refresh Sequence #{index}"
            for step in range(5):
                events.append(
                    EventTelemetry(
                        event_id=f"evt-{sc_id}-{step+1}",
                        scenario_id=sc_id,
                        timestamp_epoch_ms=base_time + (step * 250),
                        http_method="GET",
                        url=f"/api/v1/customers/{cust_id}/summary",
                        normalized_route="/api/v1/customers/{id}/summary",
                        status_code=200,
                        user_id=user_id,
                        auth_subject=user_id,
                        tenant_id=tenant_id,
                        source_ip=ip,
                        customer_id=cust_id,
                        resource_owner_id=cust_id,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["accounts", "totalBalance"],
                        response_bytes=850,
                        correlation_id=f"corr-{sc_id}-{step+1}",
                    )
                )

        meta = ScenarioGroundTruth(
            scenario_id=sc_id,
            scenario_family="BENIGN_OPERATIONS",
            scenario_name=name,
            category=GroundTruthCategory.BENIGN,
            expected_detection=False,
            expected_campaign=False,
            expected_rules=[],
            seed=seed,
            num_requests=len(events),
            num_identities=1 if sub_type != 3 else 4,
            num_tenants=1,
            num_resources=len(set(e.url for e in events)),
            duration_seconds=round((events[-1].timestamp_epoch_ms - events[0].timestamp_epoch_ms) / 1000.0, 2),
            description="Authorized clean benign banking operations.",
        )
        return meta, events

    def _generate_malicious_legacy(
        self, sc_id: str, index: int, seed: int
    ) -> Tuple[ScenarioGroundTruth, List[EventTelemetry]]:
        attacker_num = 5000 + index
        attacker_cust = f"cust_att_{attacker_num}"
        attacker_user = f"user_att_{attacker_num}"
        attacker_tenant = f"tenant_{index % 3 + 1}"
        ip = f"198.51.100.{index % 250 + 1}"
        events: List[EventTelemetry] = []
        sub_type = index % 7
        base_time = 1732185000000 + (index * 60000)

        if sub_type == 0:
            name = f"Confirmed Cross-Tenant BOLA Data Leak #{index}"
            victim_cust = f"cust_vic_{index * 10}"
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-1",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/customers/{victim_cust}",
                    normalized_route="/api/v1/customers/{id}",
                    status_code=200,
                    user_id=attacker_user,
                    auth_subject=attacker_user,
                    tenant_id=attacker_tenant,
                    source_ip=ip,
                    customer_id=attacker_cust,
                    resource_owner_id=victim_cust,
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["id", "name", "email", "phone", "ssn"],
                    response_bytes=680,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )
            expected_rules = ["RULE-BOLA-CONFIRMED-01"]
            exp_camp = False
        elif sub_type == 1:
            name = f"BOLA Account Enumeration Campaign #{index}"
            expected_rules = ["RULE-BOLA-01", "RULE-BOLA-02"]
            exp_camp = False
            for step in range(4):
                victim_acc = f"acc_vic_{index}_{step}"
                events.append(
                    EventTelemetry(
                        event_id=f"evt-{sc_id}-{step+1}",
                        scenario_id=sc_id,
                        timestamp_epoch_ms=base_time + (step * 800),
                        http_method="GET",
                        url=f"/api/v1/accounts/{victim_acc}",
                        normalized_route="/api/v1/accounts/{id}",
                        status_code=403,
                        user_id=attacker_user,
                        auth_subject=attacker_user,
                        tenant_id=attacker_tenant,
                        source_ip=ip,
                        customer_id=attacker_cust,
                        resource_owner_id=f"cust_other_{step}",
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["error"],
                        response_bytes=130,
                        correlation_id=f"corr-{sc_id}-{step+1}",
                    )
                )
        elif sub_type == 2:
            name = f"Rapid Burst Customer Harvesting #{index}"
            expected_rules = ["RULE-BULK-EXTRACT-01"]
            exp_camp = False
            for step in range(4):
                victim_cust = f"cust_harvest_{index}_{step}"
                events.append(
                    EventTelemetry(
                        event_id=f"evt-{sc_id}-{step+1}",
                        scenario_id=sc_id,
                        timestamp_epoch_ms=base_time + (step * 1200),
                        http_method="GET",
                        url=f"/api/v1/customers/{victim_cust}",
                        normalized_route="/api/v1/customers/{id}",
                        status_code=200,
                        user_id=attacker_user,
                        auth_subject=attacker_user,
                        tenant_id=attacker_tenant,
                        source_ip=ip,
                        customer_id=attacker_cust,
                        resource_owner_id=victim_cust,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["id", "name", "balance"],
                        response_bytes=520,
                        correlation_id=f"corr-{sc_id}-{step+1}",
                    )
                )
        elif sub_type == 3:
            name = f"Low-and-Slow Stealth Extraction #{index}"
            expected_rules = ["RULE-ADV-EXTRACT-01"]
            exp_camp = False
            for step in range(5):
                victim_cust = f"cust_stealth_{index}_{step}"
                events.append(
                    EventTelemetry(
                        event_id=f"evt-{sc_id}-{step+1}",
                        scenario_id=sc_id,
                        timestamp_epoch_ms=base_time + (step * 75000),
                        http_method="GET",
                        url=f"/api/v1/customers/{victim_cust}",
                        normalized_route="/api/v1/customers/{id}",
                        status_code=200,
                        user_id=attacker_user,
                        auth_subject=attacker_user,
                        tenant_id=attacker_tenant,
                        source_ip=ip,
                        customer_id=attacker_cust,
                        resource_owner_id=victim_cust,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["id", "name"],
                        response_bytes=410,
                        correlation_id=f"corr-{sc_id}-{step+1}",
                    )
                )
        elif sub_type == 4:
            name = f"Excessive Secret Data Exposure #{index}"
            expected_rules = ["RULE-EXCESSIVE-EXPOSURE-01"]
            exp_camp = False
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-1",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/customers/{attacker_cust}/internal-debug",
                    normalized_route="/api/v1/customers/{id}/internal-debug",
                    status_code=200,
                    user_id=attacker_user,
                    auth_subject=attacker_user,
                    tenant_id=attacker_tenant,
                    source_ip=ip,
                    customer_id=attacker_cust,
                    resource_owner_id=attacker_cust,
                    sensitivity="RESTRICTED",
                    observed_fields=["id", "auth_token_hash", "temporary_cleartext_secret", "master_key"],
                    response_bytes=890,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )
        elif sub_type == 5:
            name = f"Automated Sensitive Table Pagination Harvesting #{index}"
            expected_rules = ["RULE-ADV-EXTRACT-01"]
            exp_camp = False
            for p in range(1, 5):
                events.append(
                    EventTelemetry(
                        event_id=f"evt-{sc_id}-{p}",
                        scenario_id=sc_id,
                        timestamp_epoch_ms=base_time + ((p - 1) * 600),
                        http_method="GET",
                        url=f"/api/v1/customers/all?page={p}&size=50",
                        normalized_route="/api/v1/customers/all",
                        status_code=200,
                        user_id=attacker_user,
                        auth_subject=attacker_user,
                        tenant_id=attacker_tenant,
                        source_ip=ip,
                        customer_id=attacker_cust,
                        resource_owner_id=None,
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["records", "page", "size"],
                        page_number=p,
                        page_size=50,
                        response_bytes=15000,
                        correlation_id=f"corr-{sc_id}-{p}",
                    )
                )
        else:
            name = f"Multi-Stage Exfiltration Intrusion Campaign #{index}"
            expected_rules = ["RULE-PROBE-01", "RULE-BOLA-01", "RULE-BULK-EXTRACT-01", "DATA_EXFILTRATION_CAMPAIGN"]
            exp_camp = True
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-1",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url="/actuator/env",
                    normalized_route="/actuator/env",
                    status_code=404,
                    user_id=attacker_user,
                    auth_subject=attacker_user,
                    tenant_id=attacker_tenant,
                    source_ip=ip,
                    customer_id=attacker_cust,
                    resource_owner_id=None,
                    sensitivity="UNKNOWN",
                    observed_fields=["error"],
                    response_bytes=90,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-2",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time + 5000,
                    http_method="GET",
                    url="/api/v1/accounts/acc_victim_stage2",
                    normalized_route="/api/v1/accounts/{id}",
                    status_code=403,
                    user_id=attacker_user,
                    auth_subject=attacker_user,
                    tenant_id=attacker_tenant,
                    source_ip=ip,
                    customer_id=attacker_cust,
                    resource_owner_id="cust_victim_stage2",
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["error"],
                    response_bytes=130,
                    correlation_id=f"corr-{sc_id}-2",
                )
            )
            for step in range(3):
                events.append(
                    EventTelemetry(
                        event_id=f"evt-{sc_id}-{step+3}",
                        scenario_id=sc_id,
                        timestamp_epoch_ms=base_time + 12000 + (step * 1000),
                        http_method="GET",
                        url=f"/api/v1/customers/cust_exfil_target_{step}",
                        normalized_route="/api/v1/customers/{id}",
                        status_code=200,
                        user_id=attacker_user,
                        auth_subject=attacker_user,
                        tenant_id=attacker_tenant,
                        source_ip=ip,
                        customer_id=attacker_cust,
                        resource_owner_id=f"cust_exfil_target_{step}",
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["id", "name", "balance"],
                        response_bytes=600,
                        correlation_id=f"corr-{sc_id}-{step+3}",
                    )
                )

        meta = ScenarioGroundTruth(
            scenario_id=sc_id,
            scenario_family="ATTACK_CAMPAIGNS",
            scenario_name=name,
            category=GroundTruthCategory.MALICIOUS,
            expected_detection=True,
            expected_campaign=exp_camp,
            expected_rules=expected_rules,
            seed=seed,
            num_requests=len(events),
            num_identities=1,
            num_tenants=2 if sub_type == 0 else 1,
            num_resources=len(set(e.url for e in events)),
            duration_seconds=round((events[-1].timestamp_epoch_ms - events[0].timestamp_epoch_ms) / 1000.0, 2),
            description="Active unauthorized security intrusion or exfiltration attempt.",
        )
        return meta, events

    def _generate_ambiguous_legacy(
        self, sc_id: str, index: int, seed: int
    ) -> Tuple[ScenarioGroundTruth, List[EventTelemetry]]:
        events: List[EventTelemetry] = []
        base_time = 1732190000000 + (index * 60000)
        sub_type = index % 5

        if sub_type == 0:
            name = f"Ambiguous Missing Ownership Context #{index}"
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-1",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/legacy/records/{index}",
                    normalized_route="/api/v1/legacy/records/{id}",
                    status_code=200,
                    user_id=f"user_amb_{index}",
                    auth_subject=f"user_amb_{index}",
                    tenant_id=f"tenant_{index % 3 + 1}",
                    source_ip="10.0.4.1",
                    customer_id=f"cust_amb_{index}",
                    resource_owner_id=None,
                    sensitivity="UNKNOWN",
                    observed_fields=["record_id", "data"],
                    response_bytes=300,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )
        elif sub_type == 1:
            name = f"Ambiguous Missing Tenant Header #{index}"
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-1",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/customers/cust_unk_{index}",
                    normalized_route="/api/v1/customers/{id}",
                    status_code=200,
                    user_id=f"user_unk_{index}",
                    auth_subject=f"user_unk_{index}",
                    tenant_id=None,
                    source_ip="172.16.0.22",
                    customer_id=f"cust_unk_{index}",
                    resource_owner_id=f"cust_unk_{index}",
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["id", "name"],
                    response_bytes=350,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )
        elif sub_type == 2:
            name = f"Ambiguous Schema Drift Unclassified Endpoint #{index}"
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-1",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/beta/features/{index}",
                    normalized_route="/api/v1/beta/features/{id}",
                    status_code=200,
                    user_id=f"user_beta_{index}",
                    auth_subject=f"user_beta_{index}",
                    tenant_id="tenant_1",
                    source_ip="10.10.1.5",
                    customer_id=f"cust_beta_{index}",
                    resource_owner_id=f"cust_beta_{index}",
                    sensitivity="UNKNOWN",
                    observed_fields=["featureFlag", "rawMetadata"],
                    response_bytes=510,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )
        elif sub_type == 3:
            name = f"Ambiguous Misspelled Route 404 #{index}"
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-1",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url="/api/v1/cutomers/profile",
                    normalized_route="/api/v1/cutomers/profile",
                    status_code=404,
                    user_id=f"user_typo_{index}",
                    auth_subject=f"user_typo_{index}",
                    tenant_id="tenant_1",
                    source_ip="192.168.1.99",
                    customer_id=f"cust_typo_{index}",
                    resource_owner_id=None,
                    sensitivity="UNKNOWN",
                    observed_fields=["error"],
                    response_bytes=110,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )
        else:
            name = f"Ambiguous Solitary 403 Access Attempt #{index}"
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-1",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/accounts/acc_test_{index}",
                    normalized_route="/api/v1/accounts/{id}",
                    status_code=403,
                    user_id=f"user_sol_{index}",
                    auth_subject=f"user_sol_{index}",
                    tenant_id="tenant_2",
                    source_ip="10.2.2.1",
                    customer_id=f"cust_sol_{index}",
                    resource_owner_id=f"cust_other_{index}",
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["error"],
                    response_bytes=130,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )

        meta = ScenarioGroundTruth(
            scenario_id=sc_id,
            scenario_family="AMBIGUOUS_CONDITIONS",
            scenario_name=name,
            category=GroundTruthCategory.AMBIGUOUS,
            expected_detection=False,
            expected_campaign=False,
            expected_rules=[],
            seed=seed,
            num_requests=len(events),
            num_identities=1,
            num_tenants=1,
            num_resources=len(set(e.url for e in events)),
            duration_seconds=round((events[-1].timestamp_epoch_ms - events[0].timestamp_epoch_ms) / 1000.0, 2),
            description="Ambiguous operational telemetry with incomplete context.",
        )
        return meta, events

    def _generate_incomplete_legacy(
        self, sc_id: str, index: int, seed: int
    ) -> Tuple[ScenarioGroundTruth, List[EventTelemetry]]:
        events: List[EventTelemetry] = []
        base_time = 1732195000000 + (index * 60000)
        sub_type = index % 4

        if sub_type == 0:
            name = f"Incomplete Evidence Dropped Payload Body #{index}"
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-1",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/customers/cust_drop_{index}",
                    normalized_route="/api/v1/customers/{id}",
                    status_code=200,
                    user_id=f"user_drop_{index}",
                    auth_subject=f"user_drop_{index}",
                    tenant_id="tenant_1",
                    source_ip="10.8.0.1",
                    customer_id=f"cust_drop_{index}",
                    resource_owner_id=f"cust_drop_{index}",
                    sensitivity="CONFIDENTIAL",
                    observed_fields=[],
                    response_bytes=0,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )
        elif sub_type == 1:
            name = f"Incomplete Interrupted Campaign Recon Only #{index}"
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-1",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url="/actuator/health",
                    normalized_route="/actuator/health",
                    status_code=404,
                    user_id=f"user_int_{index}",
                    auth_subject=f"user_int_{index}",
                    tenant_id="tenant_1",
                    source_ip="198.51.100.77",
                    customer_id=f"cust_int_{index}",
                    resource_owner_id=None,
                    sensitivity="UNKNOWN",
                    observed_fields=["status"],
                    response_bytes=80,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )
        elif sub_type == 2:
            name = f"Incomplete Unspecified Service Contract #{index}"
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-1",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time,
                    http_method="POST",
                    url="/api/v1/external/third-party/webhook",
                    normalized_route="/api/v1/external/third-party/webhook",
                    status_code=202,
                    user_id=None,
                    auth_subject=None,
                    tenant_id=None,
                    source_ip="203.0.113.190",
                    customer_id=None,
                    resource_owner_id=None,
                    sensitivity="UNKNOWN",
                    observed_fields=["payloadId", "hookTimestamp"],
                    response_bytes=140,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )
        else:
            name = f"Incomplete Partial Multi-Domain Sequence #{index}"
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-1",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url=f"/api/v1/customers/cust_part_{index}",
                    normalized_route="/api/v1/customers/{id}",
                    status_code=200,
                    user_id=f"user_part_{index}",
                    auth_subject=f"user_part_{index}",
                    tenant_id="tenant_3",
                    source_ip="198.51.100.99",
                    customer_id=f"cust_part_{index}",
                    resource_owner_id=f"cust_part_{index}",
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["id", "balance"],
                    response_bytes=380,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )

        meta = ScenarioGroundTruth(
            scenario_id=sc_id,
            scenario_family="INCOMPLETE_EVIDENCE",
            scenario_name=name,
            category=GroundTruthCategory.INCOMPLETE_EVIDENCE,
            expected_detection=False,
            expected_campaign=False,
            expected_rules=[],
            seed=seed,
            num_requests=len(events),
            num_identities=1,
            num_tenants=1,
            num_resources=len(set(e.url for e in events)),
            duration_seconds=round((events[-1].timestamp_epoch_ms - events[0].timestamp_epoch_ms) / 1000.0, 2),
            description="Incomplete telemetry or interrupted sequence requiring uncertainty handling.",
        )
        return meta, events


# =============================================================================
# Helper Utilities: Artifact Storage, Multi-Hash Verification & Leakage Auditing
# =============================================================================

def save_dataset_artifacts(
    manifest: DatasetManifest,
    ground_truth: GroundTruthArtifact,
    telemetry_map: Dict[str, List[EventTelemetry]],
    output_dir: Path,
) -> Tuple[Path, Path, Path]:
    """Persists dataset manifest, ground-truth, and telemetry JSON files deterministically."""
    output_dir.mkdir(parents=True, exist_ok=True)

    manifest_file = output_dir / "dataset_manifest_v1_1.json"
    ground_truth_file = output_dir / "ground_truth_v1_1.json"
    telemetry_file = output_dir / "dataset_telemetry_v1_1.json"

    # 1. Telemetry Artifact (contains ONLY EventTelemetry, sorted keys, zero ground truth)
    telemetry_payload = {
        sc_id: [e.model_dump() for e in events]
        for sc_id, events in sorted(telemetry_map.items())
    }
    telemetry_file.write_text(
        json.dumps(telemetry_payload, indent=2, sort_keys=True),
        encoding="utf-8",
    )

    # 2. Ground-Truth Artifact (contains ground truth, expected outcomes, isolated)
    ground_truth_file.write_text(
        ground_truth.model_dump_json(indent=2),
        encoding="utf-8",
    )

    # 3. Manifest Artifact (contains structural definitions and hashes, zero ground truth)
    manifest_file.write_text(
        manifest.model_dump_json(indent=2),
        encoding="utf-8",
    )

    return manifest_file, ground_truth_file, telemetry_file


def verify_dataset_integrity(
    manifest_path: Path | str,
    ground_truth_path: Path | str,
    telemetry_path: Path | str,
) -> Dict[str, Any]:
    """Verifies all four independent cryptographic hashes across manifest, ground-truth, and telemetry."""
    manifest_p = Path(manifest_path)
    gt_p = Path(ground_truth_path)
    telemetry_p = Path(telemetry_path)

    errors: List[str] = []
    checks: Dict[str, bool] = {}

    if not manifest_p.exists():
        return {"valid": False, "checks": {}, "errors": [f"Manifest file not found: {manifest_p}"]}
    if not gt_p.exists():
        return {"valid": False, "checks": {}, "errors": [f"Ground-truth file not found: {gt_p}"]}
    if not telemetry_p.exists():
        return {"valid": False, "checks": {}, "errors": [f"Telemetry file not found: {telemetry_p}"]}

    try:
        manifest = DatasetManifest.model_validate_json(manifest_p.read_text(encoding="utf-8"))
    except Exception as e:
        return {"valid": False, "checks": {}, "errors": [f"Manifest parse error: {e}"]}

    try:
        gt_artifact = GroundTruthArtifact.model_validate_json(gt_p.read_text(encoding="utf-8"))
    except Exception as e:
        return {"valid": False, "checks": {}, "errors": [f"Ground-truth parse error: {e}"]}

    try:
        raw_telemetry = json.loads(telemetry_p.read_text(encoding="utf-8"))
        telemetry_map = {
            k: [EventTelemetry.model_validate(item) for item in v]
            for k, v in raw_telemetry.items()
        }
    except Exception as e:
        return {"valid": False, "checks": {}, "errors": [f"Telemetry parse error: {e}"]}

    # 1. Telemetry Canonical Hash
    computed_tel_hash = compute_canonical_telemetry_hash(telemetry_map)
    tel_valid = (computed_tel_hash == manifest.telemetry_hash)
    checks["telemetry_hash_match"] = tel_valid
    if not tel_valid:
        errors.append(
            f"Telemetry hash mismatch! Manifest: {manifest.telemetry_hash}, Computed: {computed_tel_hash}"
        )

    # 2. Ground Truth Canonical Hash
    computed_gt_hash = compute_canonical_ground_truth_hash(gt_artifact.scenarios)
    gt_valid = (
        computed_gt_hash == manifest.ground_truth_hash
        and computed_gt_hash == gt_artifact.ground_truth_hash
    )
    checks["ground_truth_hash_match"] = gt_valid
    if not gt_valid:
        errors.append(
            f"Ground truth hash mismatch! Manifest: {manifest.ground_truth_hash}, GT Artifact: {gt_artifact.ground_truth_hash}, Computed: {computed_gt_hash}"
        )

    # 3. Scenario Definitions Canonical Hash
    computed_sd_hash = compute_canonical_scenario_definitions_hash(manifest.scenario_definitions)
    sd_valid = (computed_sd_hash == manifest.scenario_definitions_hash)
    checks["scenario_definitions_hash_match"] = sd_valid
    if not sd_valid:
        errors.append(
            f"Scenario definitions hash mismatch! Manifest: {manifest.scenario_definitions_hash}, Computed: {computed_sd_hash}"
        )

    # 4. Manifest Master Digest Hash
    computed_manifest_hash = manifest.calculate_manifest_hash()
    man_valid = (computed_manifest_hash == manifest.manifest_hash)
    checks["manifest_hash_match"] = man_valid
    if not man_valid:
        errors.append(
            f"Manifest hash mismatch! Manifest: {manifest.manifest_hash}, Computed: {computed_manifest_hash}"
        )

    # 5. Cross-artifact Scenario ID Coherence
    manifest_scen_ids = set(sd.scenario_id for sd in manifest.scenario_definitions)
    gt_scen_ids = set(s.scenario_id for s in gt_artifact.scenarios)
    tel_scen_ids = set(telemetry_map.keys())

    id_coherence = (manifest_scen_ids == gt_scen_ids == tel_scen_ids)
    checks["scenario_id_coherence"] = id_coherence
    if not id_coherence:
        errors.append("Scenario ID sets diverge across manifest, ground-truth, and telemetry artifacts!")

    # 6. Population Counts Integrity
    count_valid = (
        len(manifest.scenario_definitions) == manifest.total_scenarios
        and len(gt_artifact.scenarios) == manifest.total_scenarios
        and len(telemetry_map) == manifest.total_scenarios
        and manifest.total_scenarios == 200
        and manifest.benign_count == 80
        and manifest.malicious_count == 70
        and manifest.ambiguous_count == 30
        and manifest.incomplete_count == 20
    )
    checks["population_counts_valid"] = count_valid
    if not count_valid:
        errors.append("Scenario population count mismatch across manifest, ground truth, and telemetry")

    # 7. Absence of Ground Truth in Manifest Scenario Definitions
    no_gt_in_manifest = all(
        not hasattr(sd, "category") and not hasattr(sd, "expected_detection")
        for sd in manifest.scenario_definitions
    )
    checks["manifest_has_no_ground_truth"] = no_gt_in_manifest
    if not no_gt_in_manifest:
        errors.append("Ground truth leaked into manifest scenario definitions!")

    is_all_valid = all(checks.values()) and len(errors) == 0
    return {
        "valid": is_all_valid,
        "dataset_id": manifest.dataset_id,
        "version": manifest.version,
        "telemetry_hash": manifest.telemetry_hash,
        "ground_truth_hash": manifest.ground_truth_hash,
        "scenario_definitions_hash": manifest.scenario_definitions_hash,
        "manifest_hash": manifest.manifest_hash,
        "checks": checks,
        "errors": errors,
    }


def audit_telemetry_label_leakage(
    telemetry_map: Dict[str, List[EventTelemetry]],
    forbidden_tokens: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Scans all event telemetry streams for any leaked ground truth labels or forbidden tokens."""
    tokens_to_check = forbidden_tokens or FORBIDDEN_LEAKED_TOKENS
    violations: List[str] = []
    total_events = 0

    fields_to_scan = [
        "event_id",
        "scenario_id",
        "http_method",
        "url",
        "normalized_route",
        "user_id",
        "auth_subject",
        "tenant_id",
        "source_ip",
        "customer_id",
        "resource_owner_id",
        "correlation_id",
    ]

    for sc_id, events in telemetry_map.items():
        for ev in events:
            total_events += 1
            ev_dict = ev.model_dump()
            for field in fields_to_scan:
                val = ev_dict.get(field)
                if val is not None and isinstance(val, str):
                    lower_val = val.lower()
                    for token in tokens_to_check:
                        if token.lower() in lower_val:
                            violations.append(
                                f"Leak in {sc_id} {ev.event_id} field '{field}'='{val}' matched token '{token}'"
                            )

            for field_name in ev.observed_fields:
                lower_f = field_name.lower()
                for token in tokens_to_check:
                    if token.lower() in lower_f:
                        violations.append(
                            f"Leak in {sc_id} {ev.event_id} observed_fields item '{field_name}' matched token '{token}'"
                        )

    return {
        "leakage_detected": len(violations) > 0,
        "total_events_scanned": total_events,
        "violation_count": len(violations),
        "violations": violations[:20],
    }
