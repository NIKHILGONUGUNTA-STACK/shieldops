# Phase 7.4 — Production SaaS Packaging & Multi-Cloud Infrastructure Runbook

## 1. Executive Summary & Objective

Phase 7.4 delivers enterprise-grade **Production SaaS Packaging and Multi-Cloud Infrastructure** for the Aegis API Security Operations Platform (ShieldOps). This milestone translates the verified application and intelligence engines into turnkey, resilient, and horizontally scalable deployment formats across on-premises container runtimes, Kubernetes clusters, and multi-cloud environments (AWS & GCP).

### 1.1 Key Capabilities Delivered

```
+----------------------------------------------------------------------------------------------------+
|                         AEGIS PRODUCTION SAAS ARCHITECTURE TIERS                                   |
+----------------------------------------------------------------------------------------------------+
|  [Ingress / CDN]        Cloudflare / AWS ALB / NGINX Ingress (TLS Termination, WAF, DDoS)          |
|                                         |                                                          |
|  [Presentation Tier]    Hardened NGINX Container (Port 8080) -> Angular 18 SOC Dashboard (SPA)     |
|                                         |                                                          |
|  [Perimeter & Security] Aegis API Security Gateway (Port 8000)                                     |
|                         - Reactive Non-Blocking TelemetryFilter                                    |
|                         - Out-of-Band Contextual Correlation & Detection Engines                   |
|                         - Zero-Trust Service-to-Service Secret Verification                        |
|                                 /       |       \                                                  |
|  [Microservices Tier]   Customer     Account   Transaction   (Spring Boot 3.5 / Java 25 Microservices)
|                          (8081)       (8082)      (8083)                                           |
|                                 \       |       /                                                  |
|  [Data & Persistence]   PostgreSQL 17 (Multi-AZ) | Redis 7.4 (Streams) | Keycloak 26 (OIDC IAM)   |
|                                         |                                                          |
|  [Observability Tier]   Prometheus v2.54 (Metrics Scraping) + Grafana v11.2 (SOC Dashboards)        |
+----------------------------------------------------------------------------------------------------+
```

1. **Multi-Stage Production Containerization:**
   - `frontend/Dockerfile`: Multi-stage build (Node 22 build $\rightarrow$ unprivileged Nginx 1.27 Alpine runtime running as UID 101).
   - `frontend/nginx.conf`: High-performance reverse proxy for `/api/` traffic with gzip compression, SPA fallback routing, and strict OWASP security headers (CSP, HSTS, X-Content-Type-Options, X-Frame-Options).
   - `services/Dockerfile` & `gateway/Dockerfile`: Hardened Temurin 25 Alpine runtime with non-root execution (UID 10001) and G1GC RAM percentage tuning.
2. **Production-Grade Docker Compose Orchestration:**
   - `infrastructure/docker/compose.prod.yml`: 9-container production topology with resource quotas (`cpus`, `memory`), persistent volumes, tuned database connection pools, health checks, and strict environment variable binding.
   - `.env.production.example`: Complete environment variable template with zero hardcoded credentials in version control.
3. **Enterprise Kubernetes Helm Chart (`infrastructure/helm/aegis`):**
   - Full Helm v2 chart with modular `values.yaml` for production cluster deployments.
   - HorizontalPodAutoscalers (`HPA`) for Gateway (3–10 replicas) and Frontend (3–8 replicas).
   - Zero-Trust Kubernetes `NetworkPolicies` restricting intra-namespace pod-to-pod communication.
   - Kubernetes `ServiceAccount` and Pod Security Standards (`runAsNonRoot: true`, drop all capabilities).
4. **Multi-Cloud Infrastructure as Code (Terraform):**
   - **AWS (`infrastructure/terraform/aws`):** Multi-AZ VPC (public, private, and database subnets), Amazon EKS 1.31 cluster with managed node groups, Amazon RDS PostgreSQL 17 Multi-AZ, and Amazon ElastiCache Redis Cluster.
   - **GCP (`infrastructure/terraform/gcp`):** Custom VPC with secondary IP ranges for GKE, private GKE cluster with Workload Identity, Cloud SQL PostgreSQL 17 regional high-availability, and Google Cloud Memorystore Redis HA.

---

## 2. Production Docker Compose Runbook

### 2.1 Prerequisites
- Docker Engine 26.0+ and Docker Compose v2.24+
- 4 CPU cores and 8GB RAM minimum allocated to Docker daemon.

### 2.2 Deployment Steps

1. **Generate Production Secrets:**
   ```bash
   cp .env.production.example .env.production
   ```
   Generate strong random keys and populate `.env.production`:
   ```bash
   # Generate 32-character base64 and hex secrets
   openssl rand -base64 32 # for POSTGRES_PASSWORD and REDIS_PASSWORD
   openssl rand -hex 32    # for AEGIS_INTERNAL_SECRET (must be >= 32 chars)
   openssl rand -base64 24 # for KEYCLOAK_ADMIN_PASSWORD and GRAFANA_ADMIN_PASSWORD
   ```

2. **Launch Production Stack:**
   ```bash
   docker compose -f infrastructure/docker/compose.prod.yml --env-file .env.production up -d --build
   ```

3. **Verify Service Health:**
   ```bash
   docker compose -f infrastructure/docker/compose.prod.yml ps
   ```
   All 9 containers (`postgres`, `redis`, `keycloak`, `customer-service`, `account-service`, `transaction-service`, `gateway`, `frontend`, `prometheus`, `grafana`) will transition to `healthy`.

4. **Access Endpoints:**
   - SOC Dashboard: `http://localhost:80`
   - Gateway Security Intelligence API: `http://localhost:8000`
   - Keycloak Administration: `http://localhost:8080`
   - Prometheus Observability: `http://localhost:9090`
   - Grafana Metrics: `http://localhost:3000`

---

## 3. Kubernetes & Helm Deployment Runbook

### 3.1 Namespace & Secret Setup

```bash
# 1. Create dedicated production namespace
kubectl create namespace aegis-production

# 2. Deploy TLS Certificate Secret (if using custom certificates)
kubectl create secret tls aegis-tls-production \
  --cert=path/to/tls.crt \
  --key=path/to/tls.key \
  -n aegis-production
```

### 3.2 Helm Chart Installation

```bash
# Lint the chart
helm lint infrastructure/helm/aegis

# Install or upgrade Aegis platform
helm upgrade --install aegis infrastructure/helm/aegis \
  --namespace aegis-production \
  --set global.domain=shieldops.io \
  --set postgresql.password="YOUR_SECURE_POSTGRES_PASSWORD" \
  --set redis.password="YOUR_SECURE_REDIS_PASSWORD" \
  --set keycloak.adminPassword="YOUR_SECURE_KEYCLOAK_PASSWORD"
```

### 3.3 Zero-Trust Network Policy Verification

The Helm chart installs 4 zero-trust `NetworkPolicies`:
1. `default-deny`: Denies all ingress/egress by default across the namespace, whitelisting only UDP/TCP port 53 to `kube-dns`.
2. `allow-ingress`: Permits Nginx Ingress controller to access port 8080 (`frontend`) and port 8000 (`gateway`).
3. `gateway-isolation`: Permits gateway egress strictly to domain microservices (8081, 8082, 8083), PostgreSQL (5432), and Redis (6379).
4. `microservices-policy`: Blocks microservices from external exposure; permits ingress exclusively from the Gateway and egress exclusively to PostgreSQL and peer dependencies.

---

## 4. Multi-Cloud Terraform Provisioning

### 4.1 Amazon Web Services (AWS EKS & RDS)

```bash
cd infrastructure/terraform/aws
terraform init
terraform plan -out=tfplan.binary
terraform apply tfplan.binary
```

**Provisioned AWS Resources:**
- Multi-AZ VPC across 3 Availability Zones with dedicated NAT Gateways.
- EKS Cluster (v1.31) with autoscaling managed node group (3 to 12 `m6i.xlarge` nodes).
- RDS PostgreSQL 17 Multi-AZ with automatic failover, KMS storage encryption, and 30-day automated backups.
- ElastiCache Redis Cluster with Multi-AZ automatic failover and encryption in-transit and at-rest.

### 4.2 Google Cloud Platform (GCP GKE & Cloud SQL)

```bash
cd infrastructure/terraform/gcp
terraform init
terraform plan -var="project_id=YOUR_GCP_PROJECT_ID" -out=tfplan.binary
terraform apply tfplan.binary
```

**Provisioned GCP Resources:**
- Private VPC with secondary subnet ranges (`10.20.0.0/16` for pods, `10.30.0.0/20` for services).
- GKE Private Cluster with Workload Identity and Shielded Node configuration.
- Regional Cloud SQL for PostgreSQL 17 High-Availability instance with point-in-time recovery.
- Cloud Memorystore Redis High-Availability instance (`STANDARD_HA`) with transit encryption.

---

## 5. High Availability, SLA & Disaster Recovery

| Metric | Target SLA | Implementation Mechanism |
| :--- | :--- | :--- |
| **Availability** | 99.95% | Multi-AZ database replication, 3+ pod replicas per microservice, rolling updates with zero downtime (`maxUnavailable: 0`). |
| **RPO (Recovery Point Objective)** | $\le 1$ minute | Continuous WAL archiving in PostgreSQL RDS / Cloud SQL, Redis append-only file (`AOF`). |
| **RTO (Recovery Time Objective)** | $\le 5$ minutes | Automated multi-AZ failover for PostgreSQL and Redis; automated pod rescheduling via Kubernetes. |
| **Elastic Scalability** | $\le 45$ seconds | Kubernetes HorizontalPodAutoscalers (`HPA`) scale pods from 3 to 10 instances upon reaching 70% CPU threshold. |
| **Out-of-Band Resilience** | 100% Non-Blocking | In the event of Redis Streams buffer saturation or database latency spikes, client API traffic through the Gateway proceeds unimpeded. |
