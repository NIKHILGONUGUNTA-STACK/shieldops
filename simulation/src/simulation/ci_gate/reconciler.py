"""Reconciliation and contract diff engine for Shift-Left CI Gate."""

from typing import List, Dict, Tuple, Optional
import httpx

from simulation.ci_gate.models import (
    OperationDiff,
    GateFinding,
    Severity,
    FindingType,
)
from simulation.ci_gate.parser import SpecParser


class SpecReconciler:
    """Computes structural diffs between two OpenAPI revisions and checks against Gateway telemetry."""

    @staticmethod
    def compare_specs(base: SpecParser, candidate: SpecParser) -> Tuple[List[OperationDiff], List[GateFinding]]:
        """Compares base (production) and candidate (PR) specs to detect breaking changes."""
        diffs: List[OperationDiff] = []
        breaking_findings: List[GateFinding] = []

        base_ops = SpecReconciler._extract_operations(base)
        candidate_ops = SpecReconciler._extract_operations(candidate)

        # 1. Check for removed endpoints (Breaking)
        for (method, path), base_info in base_ops.items():
            if (method, path) not in candidate_ops:
                diffs.append(
                    OperationDiff(
                        change_type="REMOVED",
                        method=method,
                        path=path,
                        summary=base_info.get("summary"),
                        breaking=True,
                        details=[f"Endpoint {method} {path} was removed from the specification."],
                    )
                )
                breaking_findings.append(
                    GateFinding(
                        id=f"RULE-GATE-BREAK-{len(breaking_findings) + 1}",
                        severity=Severity.HIGH,
                        finding_type=FindingType.BREAKING_ENDPOINT_REMOVAL,
                        method=method,
                        path=path,
                        message=f"Breaking Change: Previously published endpoint '{method} {path}' has been removed.",
                        remediation="Mark endpoint as deprecated (deprecated: true) instead of removing to maintain backward compatibility.",
                        breaking=True,
                    )
                )

        # 2. Check for added endpoints
        for (method, path), cand_info in candidate_ops.items():
            if (method, path) not in base_ops:
                diffs.append(
                    OperationDiff(
                        change_type="ADDED",
                        method=method,
                        path=path,
                        summary=cand_info.get("summary"),
                        breaking=False,
                        details=[f"New endpoint {method} {path} added in revision."],
                    )
                )
            else:
                # 3. Check for modified parameters
                base_info = base_ops[(method, path)]
                param_diffs = SpecReconciler._check_parameters(base_info, cand_info)
                if param_diffs:
                    is_breaking = any(p["breaking"] for p in param_diffs)
                    details = [p["message"] for p in param_diffs]
                    diffs.append(
                        OperationDiff(
                            change_type="MODIFIED",
                            method=method,
                            path=path,
                            summary=cand_info.get("summary"),
                            breaking=is_breaking,
                            details=details,
                        )
                    )
                    for p in param_diffs:
                        if p["breaking"]:
                            breaking_findings.append(
                                GateFinding(
                                    id=f"RULE-GATE-PARAM-{len(breaking_findings) + 1}",
                                    severity=Severity.HIGH,
                                    finding_type=FindingType.BREAKING_PARAM_REQUIRED,
                                    method=method,
                                    path=path,
                                    message=p["message"],
                                    remediation="New parameters in existing endpoints must be optional (required: false) or introduced with a new API version.",
                                    breaking=True,
                                )
                            )
                else:
                    diffs.append(
                        OperationDiff(
                            change_type="UNCHANGED",
                            method=method,
                            path=path,
                            summary=cand_info.get("summary"),
                            breaking=False,
                        )
                    )

        return diffs, breaking_findings

    @staticmethod
    def reconcile_with_gateway(
        gateway_url: str,
        candidate: SpecParser,
        token: Optional[str] = None,
        timeout_seconds: float = 5.0,
    ) -> List[GateFinding]:
        """Queries running ShieldOps Gateway reconciliation API to detect shadow routes on wire telemetry."""
        shadow_findings: List[GateFinding] = []
        headers = {}
        if token:
            headers["Authorization"] = f"Bearer {token}"

        clean_url = gateway_url.rstrip("/")
        endpoint = f"{clean_url}/api/v1/security/reconciliation/summary"

        try:
            with httpx.Client(timeout=timeout_seconds) as client:
                resp = client.get(endpoint, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    shadow_count = data.get("undocumentedEndpointsCount", 0)
                    if shadow_count > 0:
                        shadow_findings.append(
                            GateFinding(
                                id="RULE-GATE-SHADOW-01",
                                severity=Severity.HIGH,
                                finding_type=FindingType.SHADOW_ROUTE_DETECTED,
                                method="ANY",
                                path="/*",
                                message=f"Gateway reconciliation detected {shadow_count} active shadow endpoints on live wire telemetry not present in documentation.",
                                remediation="Review uninventoried endpoints in ShieldOps SOC Dashboard (/api-inventory) and ingest specifications.",
                                breaking=False,
                                details=data,
                            )
                        )
        except Exception:
            # Gracefully handle unreachable Gateway in isolated/offline CI runner
            pass

        return shadow_findings

    @staticmethod
    def _extract_operations(spec: SpecParser) -> Dict[Tuple[str, str], Dict[str, Any]]:
        ops: Dict[Tuple[str, str], Dict[str, Any]] = {}
        paths = spec.raw_data.get("paths", {})
        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue
            for method in ["get", "post", "put", "delete", "patch"]:
                if method in path_item and isinstance(path_item[method], dict):
                    ops[(method.upper(), path)] = path_item[method]
        return ops

    @staticmethod
    def _check_parameters(base_op: Dict[str, Any], cand_op: Dict[str, Any]) -> List[Dict[str, Any]]:
        diffs = []
        base_params = {p.get("name"): p for p in base_op.get("parameters", []) if isinstance(p, dict)}
        cand_params = {p.get("name"): p for p in cand_op.get("parameters", []) if isinstance(p, dict)}

        for name, cp in cand_params.items():
            if name not in base_params:
                if cp.get("required", False):
                    diffs.append({
                        "breaking": True,
                        "message": f"Newly added parameter '{name}' is marked required.",
                    })
            else:
                bp = base_params[name]
                if not bp.get("required", False) and cp.get("required", False):
                    diffs.append({
                        "breaking": True,
                        "message": f"Existing optional parameter '{name}' was changed to required.",
                    })

        return diffs
