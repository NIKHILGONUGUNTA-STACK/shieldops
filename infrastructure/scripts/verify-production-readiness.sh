#!/usr/bin/env bash
# =========================================================================
# AEGIS PHASE 7.4 — PRODUCTION DEPLOYMENT ASSET VERIFICATION SCRIPT (POSIX)
# =========================================================================
set -euo pipefail

echo "============================================================"
echo "  AEGIS PRODUCTION READINESS & ASSET VALIDATION (POSIX)"
echo "============================================================"

PASSED=0
TOTAL=0

assert_file() {
    local file="$1"
    local desc="$2"
    TOTAL=$((TOTAL + 1))
    if [[ -f "$file" ]]; then
        echo "  [PASS] $desc ($file)"
        PASSED=$((PASSED + 1))
    else
        echo "  [FAIL] Missing file: $desc ($file)"
        exit 1
    fi
}

echo ""
echo "1. Verifying Container Assets..."
assert_file "frontend/Dockerfile" "Frontend Production Multi-Stage Dockerfile"
assert_file "frontend/nginx.conf" "Frontend Production Nginx Configuration"
assert_file "frontend/.dockerignore" "Frontend Dockerignore"
assert_file "gateway/Dockerfile" "Gateway Production Dockerfile"
assert_file "services/Dockerfile" "Microservices Production Dockerfile"

echo ""
echo "2. Verifying Production Docker Compose..."
assert_file "infrastructure/docker/compose.prod.yml" "Production Docker Compose File"
assert_file ".env.production.example" "Production Environment Template"

echo ""
echo "3. Verifying Kubernetes Helm Chart..."
assert_file "infrastructure/helm/aegis/Chart.yaml" "Helm Chart Metadata"
assert_file "infrastructure/helm/aegis/values.yaml" "Helm Values Specification"
assert_file "infrastructure/helm/aegis/templates/_helpers.tpl" "Helm Template Helpers"
assert_file "infrastructure/helm/aegis/templates/deployment-gateway.yaml" "Gateway Deployment Template"
assert_file "infrastructure/helm/aegis/templates/deployment-frontend.yaml" "Frontend Deployment Template"
assert_file "infrastructure/helm/aegis/templates/deployment-microservices.yaml" "Microservices Deployment Template"
assert_file "infrastructure/helm/aegis/templates/services.yaml" "Services Routing Template"
assert_file "infrastructure/helm/aegis/templates/ingress.yaml" "Ingress Template"
assert_file "infrastructure/helm/aegis/templates/hpa.yaml" "HorizontalPodAutoscaler Template"
assert_file "infrastructure/helm/aegis/templates/networkpolicies.yaml" "Zero-Trust NetworkPolicies Template"

echo ""
echo "4. Verifying Multi-Cloud Terraform Modules..."
assert_file "infrastructure/terraform/aws/main.tf" "AWS Provider Config"
assert_file "infrastructure/terraform/aws/vpc.tf" "AWS Multi-AZ VPC Architecture"
assert_file "infrastructure/terraform/aws/eks.tf" "AWS EKS Cluster & Node Groups"
assert_file "infrastructure/terraform/aws/rds.tf" "AWS RDS PostgreSQL Multi-AZ"
assert_file "infrastructure/terraform/aws/elasticache.tf" "AWS ElastiCache Redis Cluster"
assert_file "infrastructure/terraform/aws/outputs.tf" "AWS Architecture Outputs"

assert_file "infrastructure/terraform/gcp/main.tf" "GCP Provider Config"
assert_file "infrastructure/terraform/gcp/vpc.tf" "GCP VPC Architecture"
assert_file "infrastructure/terraform/gcp/gke.tf" "GCP GKE Private Cluster"
assert_file "infrastructure/terraform/gcp/cloudsql.tf" "GCP Cloud SQL High-Availability"
assert_file "infrastructure/terraform/gcp/memorystore.tf" "GCP Memorystore Redis HA"
assert_file "infrastructure/terraform/gcp/outputs.tf" "GCP Architecture Outputs"

echo ""
echo "============================================================"
echo "  VERIFICATION COMPLETE: $PASSED / $TOTAL CHECKS PASSED (100%)"
echo "============================================================"
