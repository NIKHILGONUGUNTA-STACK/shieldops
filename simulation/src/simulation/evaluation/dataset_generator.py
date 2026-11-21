"""Deterministic Scenario Dataset Generator for Phase 7.3.6.

Generates 200 independently defined scenario executions across 4 ground-truth categories:
- 80 Benign
- 70 Malicious
- 30 Ambiguous
- 20 Incomplete Evidence

Produces:
1. Versioned DatasetManifest with deterministic SHA-256 hash.
2. Normalized telemetry event streams completely isolated from ground-truth labels.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import random
from typing import Dict, List, Tuple

from simulation.evaluation.models import (
    DatasetManifest,
    EventTelemetry,
    GroundTruthCategory,
    ScenarioGroundTruth,
)


class EvaluationDatasetGenerator:
    """Generates reproducible, statistically defensible 200-scenario evaluation datasets."""

    def __init__(self, master_seed: int = 42) -> None:
        self.master_seed = master_seed

    def generate_dataset(
        self,
        dataset_id: str = "DS-AEGIS-RESEARCH-V1",
        version: str = "1.0.0",
    ) -> Tuple[DatasetManifest, Dict[str, List[EventTelemetry]]]:
        """Generates 200 scenario ground truths and their raw event telemetry streams."""
        scenarios: List[ScenarioGroundTruth] = []
        telemetry_map: Dict[str, List[EventTelemetry]] = {}

        rng = random.Random(self.master_seed)

        # 1. 80 BENIGN SCENARIOS
        for idx in range(1, 81):
            sc_id = f"EVAL-BENIGN-{idx:03d}"
            seed = rng.randint(100000, 999999)
            meta, events = self._generate_benign_scenario(sc_id, idx, seed)
            scenarios.append(meta)
            telemetry_map[sc_id] = events

        # 2. 70 MALICIOUS SCENARIOS
        for idx in range(1, 71):
            sc_id = f"EVAL-MALICIOUS-{idx:03d}"
            seed = rng.randint(100000, 999999)
            meta, events = self._generate_malicious_scenario(sc_id, idx, seed)
            scenarios.append(meta)
            telemetry_map[sc_id] = events

        # 3. 30 AMBIGUOUS SCENARIOS
        for idx in range(1, 31):
            sc_id = f"EVAL-AMBIGUOUS-{idx:03d}"
            seed = rng.randint(100000, 999999)
            meta, events = self._generate_ambiguous_scenario(sc_id, idx, seed)
            scenarios.append(meta)
            telemetry_map[sc_id] = events

        # 4. 20 INCOMPLETE EVIDENCE SCENARIOS
        for idx in range(1, 21):
            sc_id = f"EVAL-INCOMPLETE-{idx:03d}"
            seed = rng.randint(100000, 999999)
            meta, events = self._generate_incomplete_scenario(sc_id, idx, seed)
            scenarios.append(meta)
            telemetry_map[sc_id] = events

        manifest = DatasetManifest(
            dataset_id=dataset_id,
            version=version,
            created_at=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            total_scenarios=len(scenarios),
            benign_count=80,
            malicious_count=70,
            ambiguous_count=30,
            incomplete_count=20,
            scenarios=scenarios,
        )
        manifest.manifest_hash = manifest.calculate_hash()

        return manifest, telemetry_map

    # -------------------------------------------------------------------------
    # Scenario Generators (Clean telemetry generation without ground-truth contamination)
    # -------------------------------------------------------------------------

    def _generate_benign_scenario(
        self, sc_id: str, index: int, seed: int
    ) -> Tuple[ScenarioGroundTruth, List[EventTelemetry]]:
        rng = random.Random(seed)
        cust_num = 1000 + index
        cust_id = f"cust_{cust_num}"
        user_id = f"user_{cust_num}"
        tenant_id = f"tenant_{index % 5 + 1}"
        ip = "192.168.1.50" if index % 7 == 0 else f"10.0.{index // 256}.{index % 254 + 1}"
        events: List[EventTelemetry] = []

        sub_type = index % 8
        base_time = 1732180000000 + (index * 60000)

        if sub_type == 0:
            # Standard single customer read journey
            name = f"Benign Customer Profile & Account Check #{index}"
            num_reqs = 4
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
            # Repeated legitimate reads to own account
            name = f"Benign Repeated Reads Own Account #{index}"
            num_reqs = 6
            for step in range(num_reqs):
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
            # Legitimate pagination across transaction history
            name = f"Benign Transaction Pagination #{index}"
            num_reqs = 3
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
            # Corporate NAT / shared IP legitimate employees
            name = f"Benign Shared Corporate NAT Session #{index}"
            num_reqs = 4
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
                        source_ip="203.0.113.50",  # Shared corporate proxy
                        customer_id=f"cust_nat_{cust_num}_{step}",
                        resource_owner_id=f"cust_nat_{cust_num}_{step}",
                        sensitivity="CONFIDENTIAL",
                        observed_fields=["id", "name"],
                        response_bytes=350,
                        correlation_id=f"corr-{sc_id}-{step+1}",
                    )
                )

        elif sub_type == 4:
            # Legitimate administrative denial (403 without BOLA ownership claim)
            name = f"Benign Legitimate Administrative Role Denial #{index}"
            num_reqs = 2
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
                    resource_owner_id=None,  # No customer entity ownership
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
            # Multi-resource reads owned by same customer
            name = f"Benign Multi-Account Access Same Customer #{index}"
            num_reqs = 3
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
            # Authorized transfer workflow
            name = f"Benign Legitimate Transfer Workflow #{index}"
            num_reqs = 3
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
            # High-volume legitimate query (e.g., dashboard refresh)
            name = f"Benign Dashboard Refresh Sequence #{index}"
            num_reqs = 5
            for step in range(num_reqs):
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

    def _generate_malicious_scenario(
        self, sc_id: str, index: int, seed: int
    ) -> Tuple[ScenarioGroundTruth, List[EventTelemetry]]:
        rng = random.Random(seed)
        attacker_num = 5000 + index
        attacker_cust = f"cust_att_{attacker_num}"
        attacker_user = f"user_att_{attacker_num}"
        attacker_tenant = f"tenant_{index % 3 + 1}"
        victim_tenant = f"tenant_{(index + 1) % 3 + 1}"
        ip = f"198.51.100.{index % 250 + 1}"
        events: List[EventTelemetry] = []

        sub_type = index % 7
        base_time = 1732185000000 + (index * 60000)

        if sub_type == 0:
            # Confirmed BOLA data leak (200 on cross-owner resource)
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
                    status_code=200,  # Vulnerability: 200 returned!
                    user_id=attacker_user,
                    auth_subject=attacker_user,
                    tenant_id=attacker_tenant,
                    source_ip=ip,
                    customer_id=attacker_cust,
                    resource_owner_id=victim_cust,  # MISMATCH!
                    sensitivity="CONFIDENTIAL",
                    observed_fields=["id", "name", "email", "phone", "ssn"],
                    response_bytes=680,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )
            expected_rules = ["RULE-BOLA-CONFIRMED-01"]
            exp_camp = False

        elif sub_type == 1:
            # BOLA sequential enumeration probing
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
            # Rapid bulk extraction (>= 3 distinct resources in 120s)
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
            # Low-and-slow creeping extraction (>= 5 resources across 600s)
            name = f"Low-and-Slow Stealth Extraction #{index}"
            expected_rules = ["RULE-ADV-EXTRACT-01"]
            exp_camp = False
            for step in range(5):
                victim_cust = f"cust_stealth_{index}_{step}"
                events.append(
                    EventTelemetry(
                        event_id=f"evt-{sc_id}-{step+1}",
                        scenario_id=sc_id,
                        timestamp_epoch_ms=base_time + (step * 75000),  # 75s apart
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
            # Excessive Data Exposure: restricted fields leaked
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
            # Automated pagination scraping
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
            # Full 3-stage persistent exfiltration campaign
            name = f"Multi-Stage Exfiltration Intrusion Campaign #{index}"
            expected_rules = ["RULE-PROBE-01", "RULE-BOLA-01", "RULE-BULK-EXTRACT-01", "DATA_EXFILTRATION_CAMPAIGN"]
            exp_camp = True
            # Stage 1: Recon (404 on actuator)
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
            # Stage 2: Authorization Probing (403 cross-owner)
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
            # Stage 3: Extraction (Multiple resource reads)
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

    def _generate_ambiguous_scenario(
        self, sc_id: str, index: int, seed: int
    ) -> Tuple[ScenarioGroundTruth, List[EventTelemetry]]:
        rng = random.Random(seed)
        events: List[EventTelemetry] = []
        base_time = 1732190000000 + (index * 60000)
        sub_type = index % 5

        if sub_type == 0:
            # Missing resource ownership context
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
                    resource_owner_id=None,  # Unknown ownership!
                    sensitivity="UNKNOWN",
                    observed_fields=["record_id", "data"],
                    response_bytes=300,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )

        elif sub_type == 1:
            # Missing tenant attribution
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
                    tenant_id=None,  # Missing tenant!
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
            # Uncatalogued route schema drift
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
                    sensitivity="UNKNOWN",  # Schema not registered
                    observed_fields=["featureFlag", "rawMetadata"],
                    response_bytes=510,
                    correlation_id=f"corr-{sc_id}-1",
                )
            )

        elif sub_type == 3:
            # Isolated 404 (misspelled endpoint vs recon)
            name = f"Ambiguous Misspelled Route 404 #{index}"
            events.append(
                EventTelemetry(
                    event_id=f"evt-{sc_id}-1",
                    scenario_id=sc_id,
                    timestamp_epoch_ms=base_time,
                    http_method="GET",
                    url="/api/v1/cutomers/profile",  # Typo: cutomers
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
            # Incomplete single BOLA denial without follow-up
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
            expected_detection=False,  # Should be flagged as uncertain/investigate, not confident attack
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

    def _generate_incomplete_scenario(
        self, sc_id: str, index: int, seed: int
    ) -> Tuple[ScenarioGroundTruth, List[EventTelemetry]]:
        rng = random.Random(seed)
        events: List[EventTelemetry] = []
        base_time = 1732195000000 + (index * 60000)
        sub_type = index % 4

        if sub_type == 0:
            # Missing response metadata and zero byte payload
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
                    observed_fields=[],  # Telemetry failed to extract keys!
                    response_bytes=0,    # Zero byte report
                    correlation_id=f"corr-{sc_id}-1",
                )
            )

        elif sub_type == 1:
            # Truncated campaign: Recon observed, but connection terminated
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
            # Missing OpenAPI specification for target microservice
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
            # Partial multi-domain extraction interrupted midway
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
