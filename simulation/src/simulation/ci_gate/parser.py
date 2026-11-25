"""OpenAPI 3.0 / 3.1 specification parser and Shift-Left security rule evaluation engine."""

import json
import re
from pathlib import Path
from typing import Dict, Any, List, Tuple
import yaml

from simulation.ci_gate.models import (
    GateFinding,
    GateReport,
    GateSummary,
    GateVerdict,
    Severity,
    FindingType,
)

SENSITIVE_FIELD_PATTERNS = [
    r"tax_?id",
    r"ssn",
    r"social_?security",
    r"credit_?card",
    r"card_?number",
    r"auth_?token",
    r"token_?hash",
    r"password",
    r"secret_?key",
    r"api_?key",
    r"cvv",
    r"pin_?code",
]

PUBLIC_AUTH_PATHS = {
    "/auth/login",
    "/auth/token",
    "/oauth2/token",
    "/api/v1/auth/token",
    "/actuator/health",
    "/health",
}


class SpecParser:
    """Parses OpenAPI documents and executes shift-left security compliance rules."""

    def __init__(self, spec_path: str):
        self.spec_path = Path(spec_path)
        self.raw_data: Dict[str, Any] = {}
        self._load()

    def _load(self) -> None:
        if not self.spec_path.exists():
            raise FileNotFoundError(f"OpenAPI specification not found at: {self.spec_path}")

        content = self.spec_path.read_text(encoding="utf-8")
        if self.spec_path.suffix.lower() in [".yaml", ".yml"]:
            self.raw_data = yaml.safe_load(content) or {}
        else:
            self.raw_data = json.loads(content)

    @property
    def title(self) -> str:
        return self.raw_data.get("info", {}).get("title", self.spec_path.name)

    @property
    def version(self) -> str:
        return self.raw_data.get("info", {}).get("version", "1.0.0")

    @property
    def global_security(self) -> List[Dict[str, Any]]:
        return self.raw_data.get("security", [])

    def analyze(self, posture_threshold: float = 75.0) -> Tuple[GateSummary, List[GateFinding]]:
        """Evaluates shift-left security rules on the loaded OpenAPI specification."""
        findings: List[GateFinding] = []
        paths = self.raw_data.get("paths", {})

        total_ops = 0
        authenticated_ops = 0
        unauthenticated_ops = 0

        for path, path_item in paths.items():
            if not isinstance(path_item, dict):
                continue

            for method in ["get", "post", "put", "delete", "patch", "options", "head"]:
                if method not in path_item:
                    continue

                operation = path_item[method]
                if not isinstance(operation, dict):
                    continue

                total_ops += 1
                op_method = method.upper()

                # 1. Authentication check
                has_security = bool(operation.get("security", self.global_security))
                if has_security:
                    authenticated_ops += 1
                else:
                    unauthenticated_ops += 1

                # Rule 1: Unauthenticated Mutating Operation (CRITICAL)
                if not has_security and op_method in ["POST", "PUT", "DELETE", "PATCH"]:
                    if path.lower() not in PUBLIC_AUTH_PATHS:
                        findings.append(
                            GateFinding(
                                id=f"RULE-GATE-AUTH-{len(findings) + 1}",
                                severity=Severity.CRITICAL,
                                finding_type=FindingType.UNAUTHENTICATED_MUTATING_OPERATION,
                                method=op_method,
                                path=path,
                                message=f"Mutating {op_method} operation on '{path}' lacks security requirements.",
                                remediation="Add security scheme (e.g. bearerAuth) to operation or global security block.",
                                breaking=True,
                            )
                        )
                elif not has_security and op_method == "GET":
                    if path.lower() not in PUBLIC_AUTH_PATHS and "public" not in operation.get("tags", []):
                        findings.append(
                            GateFinding(
                                id=f"RULE-GATE-AUTH-{len(findings) + 1}",
                                severity=Severity.MEDIUM,
                                finding_type=FindingType.UNAUTHENTICATED_ENDPOINT,
                                method=op_method,
                                path=path,
                                message=f"Read {op_method} operation on '{path}' is publicly accessible without authentication.",
                                remediation="Confirm whether this endpoint is intentionally public or attach security requirements.",
                                breaking=False,
                            )
                        )

                # Rule 2: Sensitive Field Exposure in Response Schema (CRITICAL)
                responses = operation.get("responses", {})
                for status_code, resp_obj in responses.items():
                    if str(status_code).startswith("2") and isinstance(resp_obj, dict):
                        schema = (
                            resp_obj.get("content", {})
                            .get("application/json", {})
                            .get("schema", {})
                        )
                        exposed_fields = self._find_sensitive_fields(schema)
                        for field_name in exposed_fields:
                            findings.append(
                                GateFinding(
                                    id=f"RULE-GATE-LEAK-{len(findings) + 1}",
                                    severity=Severity.CRITICAL,
                                    finding_type=FindingType.SENSITIVE_DATA_EXPOSURE,
                                    method=op_method,
                                    path=path,
                                    message=f"Endpoint response exposes unmasked restricted field: '{field_name}'.",
                                    remediation=f"Mask or classify '{field_name}' with privacy protection before serialization.",
                                    breaking=True,
                                    details={"field": field_name, "status_code": status_code},
                                )
                            )

                # Rule 3: Missing Ownership Validation on Object Access (HIGH)
                if re.search(r"\{[a-zA-Z0-9_]*(Id|id)\}", path):
                    desc = (operation.get("description", "") + " " + operation.get("summary", "")).lower()
                    if "ownership" not in desc and "tenant" not in desc and op_method in ["GET", "PUT", "DELETE"]:
                        findings.append(
                            GateFinding(
                                id=f"RULE-GATE-BOLA-{len(findings) + 1}",
                                severity=Severity.HIGH,
                                finding_type=FindingType.MISSING_OWNERSHIP_VALIDATION,
                                method=op_method,
                                path=path,
                                message=f"Direct object reference in path '{path}' does not specify ownership validation semantics.",
                                remediation="Ensure backend verifies authenticated subject or tenant ownership to prevent BOLA (OWASP API1:2023).",
                                breaking=False,
                            )
                        )

                # Rule 4: Insecure Path Parameter Format (LOW)
                parameters = operation.get("parameters", [])
                for param in parameters:
                    if isinstance(param, dict) and param.get("in") == "path":
                        param_name = param.get("name", "")
                        param_schema = param.get("schema", {})
                        param_type = param_schema.get("type")
                        param_format = param_schema.get("format")
                        if (
                            "id" in param_name.lower()
                            and param_type == "integer"
                            and not param_schema.get("pattern")
                        ):
                            findings.append(
                                GateFinding(
                                    id=f"RULE-GATE-FMT-{len(findings) + 1}",
                                    severity=Severity.LOW,
                                    finding_type=FindingType.INSECURE_PARAMETER_FORMAT,
                                    method=op_method,
                                    path=path,
                                    message=f"Path parameter '{param_name}' uses sequential integer identifier vulnerable to enumeration.",
                                    remediation="Use UUID format (type: string, format: uuid) to eliminate sequential identifier enumeration.",
                                    breaking=False,
                                )
                            )

        # Calculate counts
        critical_count = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high_count = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium_count = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low_count = sum(1 for f in findings if f.severity == Severity.LOW)
        breaking_count = sum(1 for f in findings if f.breaking)

        # Posture scoring (0 - 100)
        penalty = (critical_count * 25.0) + (high_count * 15.0) + (medium_count * 5.0) + (low_count * 1.0)
        posture_score = max(0.0, 100.0 - penalty)

        verdict = GateVerdict.PASSED
        if breaking_count > 0 or posture_score < posture_threshold:
            verdict = GateVerdict.FAILED
        elif high_count > 0 or medium_count > 0:
            verdict = GateVerdict.WARNING

        summary = GateSummary(
            total_operations=total_ops,
            authenticated_operations=authenticated_ops,
            unauthenticated_operations=unauthenticated_ops,
            critical_count=critical_count,
            high_count=high_count,
            medium_count=medium_count,
            low_count=low_count,
            breaking_count=breaking_count,
            posture_score=round(posture_score, 1),
            verdict=verdict,
        )

        return summary, findings

    def _find_sensitive_fields(self, schema: Dict[str, Any]) -> List[str]:
        """Recursively checks schema properties and references for sensitive field names."""
        found: List[str] = []
        if not isinstance(schema, dict):
            return found

        # Check direct properties
        props = schema.get("properties", {})
        if isinstance(props, dict):
            for prop_name in props.keys():
                for pat in SENSITIVE_FIELD_PATTERNS:
                    if re.search(pat, prop_name, re.IGNORECASE):
                        found.append(prop_name)
                        break

        # Check items for arrays
        if schema.get("type") == "array" and "items" in schema:
            found.extend(self._find_sensitive_fields(schema["items"]))

        # Check $ref in components
        ref = schema.get("$ref")
        if ref and ref.startswith("#/components/schemas/"):
            schema_name = ref.split("/")[-1]
            component_schema = (
                self.raw_data.get("components", {})
                .get("schemas", {})
                .get(schema_name, {})
            )
            found.extend(self._find_sensitive_fields(component_schema))

        return list(set(found))
