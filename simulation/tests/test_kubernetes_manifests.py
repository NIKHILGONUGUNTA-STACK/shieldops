"""Automated Verification Suite for Phase 8.0 Cloud-Native Kubernetes Infrastructure.

Validates Helm chart templates, PodDisruptionBudgets, HorizontalPodAutoscalers,
Zero-Trust NetworkPolicies, SecurityContexts, and High-Availability configurations.
"""

from pathlib import Path
import re
import yaml
import pytest


HELM_DIR = Path(__file__).resolve().parents[2] / "infrastructure" / "helm" / "aegis"
TEMPLATES_DIR = HELM_DIR / "templates"


def load_values():
    values_path = HELM_DIR / "values.yaml"
    assert values_path.exists(), f"values.yaml not found at {values_path}"
    with open(values_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def read_template(filename: str) -> str:
    template_path = TEMPLATES_DIR / filename
    assert template_path.exists(), f"Template {filename} not found at {template_path}"
    with open(template_path, "r", encoding="utf-8") as f:
        return f.read()


class TestChartMetadataAndValues:
    """Validates Helm chart metadata and configuration defaults."""

    def test_chart_metadata(self):
        chart_path = HELM_DIR / "Chart.yaml"
        assert chart_path.exists()
        with open(chart_path, "r", encoding="utf-8") as f:
            chart = yaml.safe_load(f)
        assert chart["apiVersion"] == "v2"
        assert chart["name"] == "aegis"
        assert chart["version"] == "0.2.0"
        assert chart["appVersion"] == "0.2.0"

    def test_values_structure(self):
        values = load_values()
        assert "gateway" in values
        assert "frontend" in values
        assert "microservices" in values
        assert "redis" in values
        assert "postgresql" in values
        assert "networkPolicies" in values
        assert "securityContext" in values
        assert "secretsStoreCSI" in values
        assert "envoyFilter" in values

    def test_pod_security_standards_in_values(self):
        values = load_values()
        sc = values["securityContext"]["pod"]
        assert sc["runAsNonRoot"] is True
        assert sc["runAsUser"] >= 10000
        assert sc["runAsGroup"] >= 10000
        assert sc["fsGroup"] >= 10000

        csc = values["securityContext"]["container"]
        assert csc["allowPrivilegeEscalation"] is False
        assert "ALL" in csc["capabilities"]["drop"]


class TestPodDisruptionBudgets:
    """Validates PodDisruptionBudget (PDB) HA invariants."""

    def test_pdb_template_exists(self):
        content = read_template("pdb.yaml")
        assert "kind: PodDisruptionBudget" in content
        assert "gateway-pdb" in content
        assert "frontend-pdb" in content
        assert "minAvailable" in content

    def test_pdb_values_configured(self):
        values = load_values()
        assert values["gateway"]["pdb"]["enabled"] is True
        assert values["gateway"]["pdb"]["minAvailable"] >= 2
        assert values["frontend"]["pdb"]["enabled"] is True
        assert values["frontend"]["pdb"]["minAvailable"] >= 2
        assert values["microservices"]["pdb"]["enabled"] is True
        assert values["microservices"]["pdb"]["minAvailable"] >= 1


class TestHorizontalPodAutoscalers:
    """Validates HPA configurations and metrics."""

    def test_hpa_template(self):
        content = read_template("hpa.yaml")
        assert "kind: HorizontalPodAutoscaler" in content
        assert "gateway-hpa" in content
        assert "frontend-hpa" in content
        assert "type: Resource" in content

    def test_hpa_values(self):
        values = load_values()
        gw_hpa = values["gateway"]["autoscaling"]
        assert gw_hpa["enabled"] is True
        assert gw_hpa["minReplicas"] >= 3
        assert gw_hpa["maxReplicas"] >= 5
        assert gw_hpa["targetCPUUtilizationPercentage"] <= 80

        fe_hpa = values["frontend"]["autoscaling"]
        assert fe_hpa["enabled"] is True
        assert fe_hpa["minReplicas"] >= 2
        assert fe_hpa["maxReplicas"] >= 5


class TestZeroTrustNetworkPolicies:
    """Validates NetworkPolicy isolation rules."""

    def test_network_policy_template(self):
        content = read_template("networkpolicies.yaml")
        assert "kind: NetworkPolicy" in content
        assert "default-deny" in content
        assert "allow-ingress" in content
        assert "gateway-isolation" in content
        assert "microservices-policy" in content

    def test_microservices_ingress_isolation(self):
        content = read_template("networkpolicies.yaml")
        # Ensure microservices accept ingress strictly from gateway (and peer microservices where needed)
        assert 'operator: In' in content
        assert '"gateway"' in content
        # Ensure Redis HA ports are configured
        assert "26379" in content
        assert "6379" in content


class TestRedisHighAvailability:
    """Validates Redis Sentinel HA configuration."""

    def test_redis_ha_template_exists(self):
        content = read_template("redis-ha.yaml")
        assert "kind: StatefulSet" in content
        assert "redis-ha" in content
        assert "kind: ConfigMap" in content
        assert "sentinel.conf" in content
        assert "redis-ha-master" in content
        assert "redis-ha-sentinel" in content

    def test_redis_ha_sentinel_configuration(self):
        content = read_template("redis-ha.yaml")
        assert "sentinel monitor mymaster" in content
        assert "down-after-milliseconds" in content
        assert "failover-timeout" in content
        assert "appendonly yes" in content

    def test_redis_values_ha_block(self):
        values = load_values()
        assert "ha" in values["redis"]
        ha = values["redis"]["ha"]
        assert ha["replicas"] >= 3
        assert ha["sentinelPort"] == 26379
        assert ha["quorum"] >= 2


class TestEnterpriseSecretsAndMeshIntegration:
    """Validates Secrets Store CSI driver and Envoy external authorization."""

    def test_secret_provider_class_template(self):
        content = read_template("secret-provider-class.yaml")
        assert "kind: SecretProviderClass" in content
        assert "vault-secrets" in content
        assert "AEGIS_INTERNAL_SECRET" in content

    def test_envoy_filter_template(self):
        content = read_template("envoy-filter.yaml")
        assert "kind: EnvoyFilter" in content
        assert "envoy.filters.http.ext_authz" in content
        assert "/api/v1/security/mesh/check" in content
        assert "failure_mode_allow" in content

    def test_helm_test_hook(self):
        test_path = TEMPLATES_DIR / "tests" / "test-gateway-health.yaml"
        assert test_path.exists()
        with open(test_path, "r", encoding="utf-8") as f:
            content = f.read()
        assert '"helm.sh/hook": test' in content
        assert "/actuator/health/readiness" in content


class TestResourceQuotasAndHealthProbes:
    """Validates resource quotas and probe definitions across all deployments."""

    def test_gateway_deployment_probes_and_resources(self):
        content = read_template("deployment-gateway.yaml")
        assert "livenessProbe" in content
        assert "readinessProbe" in content
        assert "resources" in content
        assert "rollingUpdate" in content
        assert "maxUnavailable: 0" in content

    def test_microservices_deployment_probes_and_resources(self):
        content = read_template("deployment-microservices.yaml")
        assert "livenessProbe" in content
        assert "readinessProbe" in content
        assert "/actuator/health/liveness" in content
        assert "/actuator/health/readiness" in content
        assert "hasKey $svc \"port\"" in content

    def test_frontend_deployment_probes_and_resources(self):
        content = read_template("deployment-frontend.yaml")
        assert "livenessProbe" in content
        assert "readinessProbe" in content
        assert "runAsNonRoot: true" in content
        assert "resources" in content
