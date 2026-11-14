"""Scenario registry for discovering and listing simulation scenarios."""

from __future__ import annotations

import logging
from typing import Type

from simulation.models import (
    ExpectedOutcome,
    ScenarioCategory,
    ScenarioMetadata,
)
from simulation.scenarios.base import BaseScenario
from simulation.scenarios.benign_customer_flow import BenignCustomerFlow
from simulation.scenarios.bola_scenarios import (
    BolaAttemptScenario,
    BolaProbeCampaignScenario,
)
from simulation.scenarios.data_leak_scenarios import (
    DataLeakScenario,
    BulkExtractScenario,
    MultiStageExfilScenario,
)
from simulation.scenarios.benign_repeated_reads_scenario import BenignRepeatedReadsScenario
from simulation.scenarios.robustness_scenarios import (
    BenignMultiResourceScenario,
    BenignConcurrentReadsScenario,
    BenignSharedIpScenario,
    BenignLegitimateDeniedScenario,
    BolaRepeatedAttemptsScenario,
    BolaConfirmedLeakScenario,
    BolaMultiIdentityTargetScenario,
    SlowExtractionScenario,
    DistributedExtractionScenario,
    EdgeMissingOwnershipScenario,
    EdgeMissingClassificationScenario,
    EdgeDuplicateEventsScenario,
    EdgeDelayedEventsScenario,
    EdgeOutOfOrderScenario,
    EdgeWindowBoundaryScenario,
    EdgeIncompleteSequenceScenario,
)
from simulation.scenarios.advanced_extraction_scenarios import (
    BenignPaginationScenario,
    BenignLargeResponseScenario,
    PaginationExtractionScenario,
    RestrictedFieldRetrievalScenario,
    MultiResourceExtractionScenario,
    CumulativeWindowExtractionScenario,
    EdgeNoResponseSizeScenario,
)
from simulation.scenarios.campaign_scenarios import (
    ReconThenBolaProbingScenario,
    BolaProbingThenExtractionScenario,
    SensitiveExposureThenBulkScenario,
    LowSlowMultiDomainScenario,
    BenignLookalikeScenario,
    MultiVectorCampaignScenario,
)

log = logging.getLogger(__name__)


class ScenarioRegistry:
    """Registry managing scenario metadata and executable classes."""

    def __init__(self) -> None:
        self._metadata_map: dict[str, ScenarioMetadata] = {}
        self._class_map: dict[str, Type[BaseScenario]] = {}

    def register_metadata(self, metadata: ScenarioMetadata) -> None:
        """Registers metadata for a scenario (including planned scenarios)."""
        self._metadata_map[metadata.id] = metadata

    def register_class(self, scenario_cls: Type[BaseScenario], metadata: ScenarioMetadata) -> None:
        """Registers an executable scenario class with its metadata."""
        self._metadata_map[metadata.id] = metadata
        self._class_map[metadata.id] = scenario_cls

    def get_metadata(self, scenario_id: str) -> ScenarioMetadata | None:
        """Retrieves metadata by scenario ID."""
        return self._metadata_map.get(scenario_id)

    def get_class(self, scenario_id: str) -> Type[BaseScenario] | None:
        """Retrieves executable scenario class if registered."""
        return self._class_map.get(scenario_id)

    def list_all(self) -> list[ScenarioMetadata]:
        """Lists all registered scenarios sorted by scenario ID."""
        return sorted(self._metadata_map.values(), key=lambda m: m.id)

    def list_by_category(self, category: ScenarioCategory) -> list[ScenarioMetadata]:
        """Lists scenarios matching a specific category."""
        return [m for m in self.list_all() if m.category == category]


def get_default_registry() -> ScenarioRegistry:
    """Constructs the standard Aegis scenario registry with all planned scenarios."""
    registry = ScenarioRegistry()

    # 1. SCEN-BENIGN-01: Legitimate Customer Banking Journey
    benign_meta = ScenarioMetadata(
        id="SCEN-BENIGN-01",
        name="Legitimate Customer Banking Journey",
        description="Authenticates as legitimate customer, checks account profile, views balances, and executes verified transfer.",
        category=ScenarioCategory.BENIGN,
        target_services=["customer-service", "account-service", "transaction-service"],
        expected_outcome=ExpectedOutcome(
            expected_status_codes=[200, 201],
            expected_detection_rules=[],
            expected_incident_severity=None,
        ),
        is_implemented=True,
    )
    registry.register_class(BenignCustomerFlow, benign_meta)

    # 2. SCEN-BOLA-01: Single Cross-Customer Unauthorized Access Attempt
    bola_01_meta = ScenarioMetadata(
        id="SCEN-BOLA-01",
        name="Broken Object Level Authorization (BOLA) Cross-Customer Access",
        description="Customer attempts to retrieve and debit accounts belonging to a different customer ID.",
        category=ScenarioCategory.BOLA,
        target_services=["customer-service", "account-service"],
        expected_outcome=ExpectedOutcome(
            expected_status_codes=[403],
            expected_detection_rules=["RULE-BOLA-01"],
            expected_incident_severity="HIGH",
        ),
        is_implemented=True,
    )
    registry.register_class(BolaAttemptScenario, bola_01_meta)

    # 3. SCEN-BOLA-02: Multi-Target BOLA Probing Campaign
    bola_02_meta = ScenarioMetadata(
        id="SCEN-BOLA-02",
        name="BOLA Probing Campaign Across Multiple Accounts",
        description="Customer sends sequential cross-owner requests targeting distinct account resources.",
        category=ScenarioCategory.BOLA,
        target_services=["account-service"],
        expected_outcome=ExpectedOutcome(
            expected_status_codes=[403],
            expected_detection_rules=["RULE-BOLA-02"],
            expected_incident_severity="HIGH",
        ),
        is_implemented=True,
    )
    registry.register_class(BolaProbeCampaignScenario, bola_02_meta)

    # 4. SCEN-DATA-LEAK-01: Sensitive Data Exposure
    data_leak_meta = ScenarioMetadata(
        id="SCEN-DATA-LEAK-01",
        name="Unexpected Sensitive Field Data Leakage",
        description="Non-analyst caller requests endpoints containing CONFIDENTIAL and RESTRICTED fields.",
        category=ScenarioCategory.DATA_ACCESS,
        target_services=["customer-service", "account-service"],
        expected_outcome=ExpectedOutcome(
            expected_status_codes=[403, 200],
            expected_detection_rules=["RULE-DATA-LEAK-01"],
            expected_incident_severity="HIGH",
        ),
        is_implemented=True,
    )
    registry.register_class(DataLeakScenario, data_leak_meta)

    # 5. SCEN-BULK-EXTRACT-01: Excessive Data Access and Extraction
    bulk_extract_meta = ScenarioMetadata(
        id="SCEN-BULK-EXTRACT-01",
        name="Excessive Bulk Data Access and Extraction",
        description="High-frequency iterative reads across >= 3 distinct customer/account resources.",
        category=ScenarioCategory.DATA_ACCESS,
        target_services=["customer-service"],
        expected_outcome=ExpectedOutcome(
            expected_status_codes=[200, 403],
            expected_detection_rules=["RULE-BULK-EXTRACT-01"],
            expected_incident_severity="HIGH",
        ),
        is_implemented=True,
    )
    registry.register_class(BulkExtractScenario, bulk_extract_meta)

    # 6. SCEN-EXFIL-01: Multi-Stage Exfiltration Campaign
    exfil_meta = ScenarioMetadata(
        id="SCEN-EXFIL-01",
        name="Multi-Stage Exfiltration Campaign",
        description="Correlated multi-stage attack: Reconnaissance -> BOLA Probing -> Data Extraction.",
        category=ScenarioCategory.MULTI_VECTOR,
        target_services=["security-gateway", "account-service", "customer-service"],
        expected_outcome=ExpectedOutcome(
            expected_status_codes=[401, 403, 404],
            expected_detection_rules=["RULE-PROBE-01", "RULE-BOLA-01", "DATA_EXFILTRATION_CAMPAIGN"],
            expected_incident_severity="CRITICAL",
        ),
        is_implemented=True,
    )
    registry.register_class(MultiStageExfilScenario, exfil_meta)

    # 7. SCEN-BENIGN-02: Legitimate Repeated Reads
    benign_02_meta = ScenarioMetadata(
        id="SCEN-BENIGN-02",
        name="Legitimate Repeated Reads (False Positive Benchmark)",
        description="High-frequency legitimate reads of owned resources to verify zero false positives.",
        category=ScenarioCategory.BENIGN,
        target_services=["customer-service", "account-service"],
        expected_outcome=ExpectedOutcome(
            expected_status_codes=[200],
            expected_detection_rules=[],
            expected_incident_severity=None,
        ),
        is_implemented=True,
    )
    registry.register_class(BenignRepeatedReadsScenario, benign_02_meta)

    # 8. SCEN-BENIGN-03: Authorized Multi-Resource Access
    registry.register_class(
        BenignMultiResourceScenario,
        ScenarioMetadata(
            id="SCEN-BENIGN-03",
            name="Authorized Multi-Resource Access",
            description="Legitimate customer accesses their profile, accounts, and transactions without cross-owner violations.",
            category=ScenarioCategory.BENIGN,
            target_services=["customer-service", "account-service", "transaction-service"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200], expected_detection_rules=[]),
            is_implemented=True,
        ),
    )

    # 9. SCEN-BENIGN-04: Concurrent Legitimate Reads
    registry.register_class(
        BenignConcurrentReadsScenario,
        ScenarioMetadata(
            id="SCEN-BENIGN-04",
            name="Concurrent Legitimate Reads",
            description="Single customer issues concurrent read operations across their own assets.",
            category=ScenarioCategory.BENIGN,
            target_services=["customer-service", "account-service"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200], expected_detection_rules=[]),
            is_implemented=True,
        ),
    )

    # 10. SCEN-BENIGN-05: Shared IP Across Different Identities
    registry.register_class(
        BenignSharedIpScenario,
        ScenarioMetadata(
            id="SCEN-BENIGN-05",
            name="Shared IP Across Distinct Customer Identities",
            description="Two distinct legitimate customers communicate through a shared corporate NAT IP.",
            category=ScenarioCategory.BENIGN,
            target_services=["customer-service"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200], expected_detection_rules=[]),
            is_implemented=True,
        ),
    )

    # 11. SCEN-BENIGN-06: Legitimate Denied Access
    registry.register_class(
        BenignLegitimateDeniedScenario,
        ScenarioMetadata(
            id="SCEN-BENIGN-06",
            name="Legitimate Denied Access (Non-BOLA 403)",
            description="Customer denied access to administrative operational route without BOLA or sensitive leakage.",
            category=ScenarioCategory.BENIGN,
            target_services=["security-gateway"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[403], expected_detection_rules=[]),
            is_implemented=True,
        ),
    )

    # 12. SCEN-BOLA-03: Repeated Cross-Owner Attempts on Single Resource
    registry.register_class(
        BolaRepeatedAttemptsScenario,
        ScenarioMetadata(
            id="SCEN-BOLA-03",
            name="Repeated Cross-Owner Resource Probing",
            description="Repeated unauthorized cross-customer attempts against a single victim resource.",
            category=ScenarioCategory.BOLA,
            target_services=["customer-service"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[403], expected_detection_rules=["RULE-BOLA-01"]),
            is_implemented=True,
        ),
    )

    # 13. SCEN-BOLA-05: Successful Unauthorized Resource Access (Confirmed Leak)
    registry.register_class(
        BolaConfirmedLeakScenario,
        ScenarioMetadata(
            id="SCEN-BOLA-05",
            name="Confirmed BOLA Leakage (HTTP 200 Cross-Owner)",
            description="Cross-owner resource access succeeds with HTTP 200 containing confidential data.",
            category=ScenarioCategory.BOLA,
            target_services=["account-service"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200], expected_detection_rules=["RULE-BOLA-CONFIRMED-01"]),
            is_implemented=True,
        ),
    )

    # 14. SCEN-BOLA-06: Different Identities Targeting One Victim Resource
    registry.register_class(
        BolaMultiIdentityTargetScenario,
        ScenarioMetadata(
            id="SCEN-BOLA-06",
            name="Multi-Identity BOLA Targeting Single Resource",
            description="Multiple distinct attacker identities attempt unauthorized access against the same victim account.",
            category=ScenarioCategory.BOLA,
            target_services=["account-service"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[403], expected_detection_rules=["RULE-BOLA-01"]),
            is_implemented=True,
        ),
    )

    # 15. SCEN-EXTRACT-SLOW: Slow Extraction (Spaced / Below Threshold)
    registry.register_class(
        SlowExtractionScenario,
        ScenarioMetadata(
            id="SCEN-EXTRACT-SLOW",
            name="Slow Data Extraction Below Threshold",
            description="Slow extraction targeting only 2 distinct resources to evaluate boundary threshold behaviour.",
            category=ScenarioCategory.DATA_ACCESS,
            target_services=["customer-service"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200], expected_detection_rules=[]),
            is_implemented=True,
        ),
    )

    # 16. SCEN-EXTRACT-DISTRIBUTED: Distributed Extraction Across Sessions
    registry.register_class(
        DistributedExtractionScenario,
        ScenarioMetadata(
            id="SCEN-EXTRACT-DISTRIBUTED",
            name="Distributed Extraction Across Identities",
            description="Extraction distributed across separate user identities to test identity isolation.",
            category=ScenarioCategory.DATA_ACCESS,
            target_services=["customer-service"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200], expected_detection_rules=[]),
            is_implemented=True,
        ),
    )

    # 17. SCEN-EDGE-NO-OWNERSHIP: Missing Ownership Metadata
    registry.register_class(
        EdgeMissingOwnershipScenario,
        ScenarioMetadata(
            id="SCEN-EDGE-NO-OWNERSHIP",
            name="Edge Case: Missing Ownership Metadata",
            description="Telemetry event lacks explicit customer ownership metadata.",
            category=ScenarioCategory.BENIGN,
            target_services=["gateway"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200], expected_detection_rules=[]),
            is_implemented=True,
        ),
    )

    # 18. SCEN-EDGE-NO-CLASSIF: Missing Sensitivity Classification
    registry.register_class(
        EdgeMissingClassificationScenario,
        ScenarioMetadata(
            id="SCEN-EDGE-NO-CLASSIF",
            name="Edge Case: Missing Sensitivity Classification",
            description="Request hits an internal route without pre-declared schema sensitivity.",
            category=ScenarioCategory.BENIGN,
            target_services=["gateway"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200], expected_detection_rules=[]),
            is_implemented=True,
        ),
    )

    # 19. SCEN-EDGE-DUPLICATE: Duplicate Event Delivery
    registry.register_class(
        EdgeDuplicateEventsScenario,
        ScenarioMetadata(
            id="SCEN-EDGE-DUPLICATE",
            name="Edge Case: Duplicate Event Delivery",
            description="Exact duplicate telemetry delivery with identical correlation ID.",
            category=ScenarioCategory.BENIGN,
            target_services=["account-service"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200], expected_detection_rules=[]),
            is_implemented=True,
        ),
    )

    # 20. SCEN-EDGE-DELAYED: Delayed Event Arrival
    registry.register_class(
        EdgeDelayedEventsScenario,
        ScenarioMetadata(
            id="SCEN-EDGE-DELAYED",
            name="Edge Case: Delayed Event Arrival",
            description="Telemetry events arriving with delay to test time-window tolerance.",
            category=ScenarioCategory.BENIGN,
            target_services=["account-service"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200], expected_detection_rules=[]),
            is_implemented=True,
        ),
    )

    # 21. SCEN-EDGE-OUT-OF-ORDER: Out-of-Order Event Sequence
    registry.register_class(
        EdgeOutOfOrderScenario,
        ScenarioMetadata(
            id="SCEN-EDGE-OUT-OF-ORDER",
            name="Edge Case: Out-of-Order Event Sequence",
            description="Extraction telemetry arrived prior to reconnaissance probes.",
            category=ScenarioCategory.DATA_ACCESS,
            target_services=["customer-service", "gateway"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200, 404], expected_detection_rules=["RULE-DATA-LEAK-01"]),
            is_implemented=True,
        ),
    )

    # 22. SCEN-EDGE-WINDOW-BOUNDARY: Sliding-Window Boundary Conditions
    registry.register_class(
        EdgeWindowBoundaryScenario,
        ScenarioMetadata(
            id="SCEN-EDGE-WINDOW-BOUNDARY",
            name="Edge Case: Sliding Window Boundary Conditions",
            description="Events right at sliding window boundary to test edge retention.",
            category=ScenarioCategory.BENIGN,
            target_services=["customer-service"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200], expected_detection_rules=[]),
            is_implemented=True,
        ),
    )

    # 23. SCEN-EDGE-INCOMPLETE-SEQUENCE: Incomplete Attack Sequence
    registry.register_class(
        EdgeIncompleteSequenceScenario,
        ScenarioMetadata(
            id="SCEN-EDGE-INCOMPLETE-SEQUENCE",
            name="Edge Case: Incomplete Attack Sequence",
            description="Reconnaissance probes that terminate without progressing to data extraction.",
            category=ScenarioCategory.PROBING,
            target_services=["gateway"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200], expected_detection_rules=["RULE-PROBE-01"]),
            is_implemented=True,
        ),
    )

    # 24. SCEN-BENIGN-PAGINATION: Legitimate Multi-Page Account History Access
    registry.register_class(
        BenignPaginationScenario,
        ScenarioMetadata(
            id="SCEN-BENIGN-PAGINATION",
            name="Legitimate Multi-Page Account History Access",
            description="Authenticates as customer and navigates account history across sequential pages.",
            category=ScenarioCategory.BENIGN,
            target_services=["account-service"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200], expected_detection_rules=[]),
            is_implemented=True,
        ),
    )

    # 25. SCEN-BENIGN-LARGE-RESP: Legitimate Large Statement Response
    registry.register_class(
        BenignLargeResponseScenario,
        ScenarioMetadata(
            id="SCEN-BENIGN-LARGE-RESP",
            name="Legitimate Bulk Statement Export Response",
            description="Legitimate high-volume account export response by authorized owner.",
            category=ScenarioCategory.BENIGN,
            target_services=["account-service"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200], expected_detection_rules=[]),
            is_implemented=True,
        ),
    )

    # 26. SCEN-EXTRACT-PAGINATION: Automated Sequential Pagination Harvesting
    registry.register_class(
        PaginationExtractionScenario,
        ScenarioMetadata(
            id="SCEN-EXTRACT-PAGINATION",
            name="Automated Pagination-Based Data Harvesting",
            description="Automated crawler iterating through paginated records to systematically harvest data.",
            category=ScenarioCategory.DATA_ACCESS,
            target_services=["account-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[200],
                expected_detection_rules=["RULE-ADV-EXTRACT-01"],
                expected_incident_severity="HIGH",
            ),
            is_implemented=True,
        ),
    )

    # 27. SCEN-DATA-RESTRICTED: Probing for Restricted Sensitive Secrets
    registry.register_class(
        RestrictedFieldRetrievalScenario,
        ScenarioMetadata(
            id="SCEN-DATA-RESTRICTED",
            name="Repeated Restricted Field Retrieval Probing",
            description="Probes customer profile endpoints for unexpected exposure of RESTRICTED secrets and tokens.",
            category=ScenarioCategory.DATA_ACCESS,
            target_services=["customer-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[200],
                expected_detection_rules=["RULE-EXCESSIVE-EXPOSURE-01"],
                expected_incident_severity="CRITICAL",
            ),
            is_implemented=True,
        ),
    )

    # 28. SCEN-EXTRACT-MULTI-RESOURCE: Cross-Domain Multi-Resource Harvesting
    registry.register_class(
        MultiResourceExtractionScenario,
        ScenarioMetadata(
            id="SCEN-EXTRACT-MULTI-RESOURCE",
            name="Cross-Domain Multi-Resource Extraction",
            description="Coordinated harvesting sequence querying Customer, Account, and Transfer resources.",
            category=ScenarioCategory.DATA_ACCESS,
            target_services=["customer-service", "account-service", "transaction-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[200],
                expected_detection_rules=["RULE-ADV-EXTRACT-01"],
                expected_incident_severity="HIGH",
            ),
            is_implemented=True,
        ),
    )

    # 29. SCEN-EXTRACT-CUMULATIVE: Cumulative High-Volume Window Extraction
    registry.register_class(
        CumulativeWindowExtractionScenario,
        ScenarioMetadata(
            id="SCEN-EXTRACT-CUMULATIVE",
            name="Cumulative High-Volume Sliding-Window Harvesting",
            description="Rapid bulk harvesting breaching cumulative volume thresholds across sliding windows.",
            category=ScenarioCategory.DATA_ACCESS,
            target_services=["account-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[200],
                expected_detection_rules=["RULE-ADV-EXTRACT-01"],
                expected_incident_severity="HIGH",
            ),
            is_implemented=True,
        ),
    )

    # 30. SCEN-EDGE-NO-RESP-SIZE: Missing Response Size Metadata
    registry.register_class(
        EdgeNoResponseSizeScenario,
        ScenarioMetadata(
            id="SCEN-EDGE-NO-RESP-SIZE",
            name="Edge Case: Missing Response-Size Metadata",
            description="Handles telemetry arrival when response size is zero or absent.",
            category=ScenarioCategory.BENIGN,
            target_services=["account-service"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200], expected_detection_rules=[]),
            is_implemented=True,
        ),
    )

    # 31. SCEN-EXFIL-RECON-PROBE: Reconnaissance Followed by BOLA Probing
    registry.register_class(
        ReconThenBolaProbingScenario,
        ScenarioMetadata(
            id="SCEN-EXFIL-RECON-PROBE",
            name="Reconnaissance Followed by BOLA Probing Campaign",
            description="Reconnaissance scans on system endpoints followed immediately by BOLA probing on customer profiles.",
            category=ScenarioCategory.MULTI_VECTOR,
            target_services=["customer-service", "gateway"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[403, 404],
                expected_detection_rules=["RULE-PROBE-01", "RULE-BOLA-01", "DATA_EXFILTRATION_CAMPAIGN"],
                expected_incident_severity="CRITICAL",
            ),
            is_implemented=True,
        ),
    )

    # 32. SCEN-EXFIL-PROBE-EXTRACT: BOLA Probing Followed by Unauthorized Extraction
    registry.register_class(
        BolaProbingThenExtractionScenario,
        ScenarioMetadata(
            id="SCEN-EXFIL-PROBE-EXTRACT",
            name="Authorization Probing Followed by Unauthorized Extraction",
            description="BOLA probing attempts culminating in successful cross-owner account extraction.",
            category=ScenarioCategory.MULTI_VECTOR,
            target_services=["customer-service", "account-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[200, 403],
                expected_detection_rules=["RULE-BOLA-01", "RULE-BOLA-CONFIRMED-01", "DATA_EXFILTRATION_CAMPAIGN"],
                expected_incident_severity="CRITICAL",
            ),
            is_implemented=True,
        ),
    )

    # 33. SCEN-EXFIL-EXPOSE-BULK: Sensitive-Field Exposure Followed by Bulk Harvesting
    registry.register_class(
        SensitiveExposureThenBulkScenario,
        ScenarioMetadata(
            id="SCEN-EXFIL-EXPOSE-BULK",
            name="Sensitive-Field Exposure Followed by Bulk Harvesting",
            description="Retrieving undeclared restricted secrets followed by rapid pagination harvesting.",
            category=ScenarioCategory.DATA_ACCESS,
            target_services=["customer-service", "account-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[200],
                expected_detection_rules=["RULE-EXCESSIVE-EXPOSURE-01", "RULE-ADV-EXTRACT-01", "DATA_EXFILTRATION_CAMPAIGN"],
                expected_incident_severity="CRITICAL",
            ),
            is_implemented=True,
        ),
    )

    # 34. SCEN-EXFIL-LOW-SLOW-MULTI: Low-and-Slow Multi-Domain Extraction Campaign
    registry.register_class(
        LowSlowMultiDomainScenario,
        ScenarioMetadata(
            id="SCEN-EXFIL-LOW-SLOW-MULTI",
            name="Low-and-Slow Multi-Domain Extraction Campaign",
            description="Creeping extraction distributed across Customer, Account, and Transfer service domains.",
            category=ScenarioCategory.DATA_ACCESS,
            target_services=["customer-service", "account-service", "transaction-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[200],
                expected_detection_rules=["RULE-ADV-EXTRACT-01", "DATA_EXFILTRATION_CAMPAIGN"],
                expected_incident_severity="HIGH",
            ),
            is_implemented=True,
        ),
    )

    # 35. SCEN-BENIGN-LOOKALIKE: Benign Activity Resembling Attack Sequence
    registry.register_class(
        BenignLookalikeScenario,
        ScenarioMetadata(
            id="SCEN-BENIGN-LOOKALIKE",
            name="Benign Lookalike: Asset 404 & Own Profile Navigation",
            description="Legitimate customer accessing missing asset followed by owned profile read (zero alarms).",
            category=ScenarioCategory.BENIGN,
            target_services=["customer-service"],
            expected_outcome=ExpectedOutcome(expected_status_codes=[200, 404], expected_detection_rules=[]),
            is_implemented=True,
        ),
    )

    # 36. SCEN-MULTI-01: Multi-Vector Coordinated Intrusion Campaign
    registry.register_class(
        MultiVectorCampaignScenario,
        ScenarioMetadata(
            id="SCEN-MULTI-01",
            name="Multi-Vector Coordinated Attack Campaign",
            description="Simulates reconnaissance probing, followed by targeted BOLA probing, leading into data retrieval.",
            category=ScenarioCategory.MULTI_VECTOR,
            target_services=["customer-service", "account-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[200, 403, 404],
                expected_detection_rules=["RULE-PROBE-01", "RULE-BOLA-01", "DATA_EXFILTRATION_CAMPAIGN"],
                expected_incident_severity="CRITICAL",
            ),
            is_implemented=True,
        ),
    )

    standard_scenarios = [
        ScenarioMetadata(
            id="SCEN-AUTH-01",
            name="Authentication Failure Burst & Credential Probing",
            description="Sends rapid burst of invalid JWT tokens and malformed credentials targeting account endpoints.",
            category=ScenarioCategory.AUTHENTICATION,
            target_services=["account-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[401],
                expected_detection_rules=["RULE-AUTH-01"],
                expected_incident_severity="MEDIUM",
            ),
            is_implemented=False,
        ),
        ScenarioMetadata(
            id="SCEN-AUTHZ-01",
            name="Unauthorized Resource Access & Privilege Escalation",
            description="Customer role attempts to access privileged SOC security APIs and administrative endpoints.",
            category=ScenarioCategory.AUTHORIZATION,
            target_services=["security-gateway"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[403],
                expected_detection_rules=["RULE-AUTH-01"],
                expected_incident_severity="MEDIUM",
            ),
            is_implemented=False,
        ),
        ScenarioMetadata(
            id="SCEN-PROBE-01",
            name="Undocumented API Route Probing & Discovery Traversal",
            description="Probes non-existent admin routes, swagger-ui, debug endpoints, and actuator perimeters.",
            category=ScenarioCategory.PROBING,
            target_services=["external-gateway", "aegis-gateway"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[404],
                expected_detection_rules=["RULE-PROBE-01"],
                expected_incident_severity="LOW",
            ),
            is_implemented=False,
        ),
        ScenarioMetadata(
            id="SCEN-INJ-01",
            name="Input Parameter Injection (SQLi & Path Traversal)",
            description="Submits SQL injection strings and traversal sequences in search, query, and reference parameters.",
            category=ScenarioCategory.INJECTION,
            target_services=["customer-service", "transaction-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[400, 404],
                expected_detection_rules=["RULE-INJ-01"],
                expected_incident_severity="CRITICAL",
            ),
            is_implemented=False,
        ),
        ScenarioMetadata(
            id="SCEN-RATE-01",
            name="API Request Burst & Transfer Rate Abuse",
            description="Fires high-frequency burst of transfer requests exceeding threshold within sliding window.",
            category=ScenarioCategory.RATE_ABUSE,
            target_services=["transaction-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[200, 429],
                expected_detection_rules=["RULE-RATE-01"],
                expected_incident_severity="HIGH",
            ),
            is_implemented=False,
        ),
        ScenarioMetadata(
            id="SCEN-DATA-01",
            name="High-Volume Customer Profile Data Scraping",
            description="Iterates sequentially through predicted UUID and customer ID ranges to scrape data.",
            category=ScenarioCategory.DATA_ACCESS,
            target_services=["customer-service"],
            expected_outcome=ExpectedOutcome(
                expected_status_codes=[200, 403, 404],
                expected_detection_rules=["RULE-PROBE-01"],
                expected_incident_severity="MEDIUM",
            ),
            is_implemented=False,
        ),
    ]

    for meta in standard_scenarios:
        registry.register_metadata(meta)

    return registry

