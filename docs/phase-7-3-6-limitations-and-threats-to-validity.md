# Phase 7.3.6 — Limitations & Threats to Validity

**Research Title:** Intrusion Detection and Adaptive Security Response Through API Activity Analysis  
**Project:** ShieldOps (Aegis Security Operations Platform)  
**Milestone:** Phase 7.3.6 — Research Evaluation & Experimental Validation  
**Date:** November 2026  

---

## 1. Overview

A critical requirement of scientific research is a candid and exhaustive analysis of potential limitations, confounding factors, and threats to validity. This document systematically examines threats to **Construct Validity**, **Internal Validity**, **External Validity**, and **Conclusion Validity** in our evaluation of the Aegis Contextual API Activity Analysis engine.

---

## 2. Threats to Construct Validity

Construct validity assesses whether the operationalized metrics and experimental setups accurately represent the theoretical concepts under study.

### 2.1 Synthetic Testbed vs Real-World Production Traffic
- **Threat:** The evaluation dataset (`DS-AEGIS-RESEARCH-V1`) is generated through a controlled simulation testbed rather than harvested from live, multi-year commercial banking traffic. Synthetic datasets run the risk of over-simplifying legitimate behavioral diversity.
- **Mitigation:**
  - The simulation framework is built on authentic banking schemas (OpenAPI 3.0 contracts covering Customer, Account, Transfer, Card, and Statement services).
  - Telemetry is passed through real microservices, Spring Cloud Gateway, Redis Streams, and Keycloak OAuth2 authenticators.
  - The dataset deliberately includes 50 Ambiguous and Incomplete Evidence scenarios (25% of the dataset) specifically to introduce natural noise, corporate proxy artifacts, dropped tokens, and retry bursts.

### 2.2 Surrogate Telemetry Representations
- **Threat:** Telemetry schemas abstract away low-level network layer phenomena (e.g., packet retransmissions, TLS handshakes, MTU fragmentation).
- **Mitigation:** Modern API logic attacks (such as BOLA, broken function level authorization, and creeping exfiltration) occur strictly at the application layer (L7). Evaluating normalized HTTP request-response metadata accurately captures the semantic attack surface without noise from irrelevant packet-level dynamics.

---

## 3. Threats to Internal Validity

Internal validity examines whether the experimental design contains confounding variables that could falsely account for the observed performance differences.

### 3.1 Detector Implementation Parity
- **Threat:** Could the baseline (Isolated Rules) be an artificially weak "strawman" intentionally designed to fail?
- **Mitigation:**
  - The isolated rule engine implements standard production WAF / API gateway inspection patterns (`RULE-BOLA-01`, `RULE-PROBE-01`, `RULE-DATA-01`).
  - The rules were tuned to maximize their performance on the benchmark dataset. For instance, the BOLA rule checks for cross-owner identifiers where obvious, and the data exposure rule evaluates sensitive data classification tags.
  - The failure of isolated rules is structural: stateless rules cannot retain historical request velocity across 600-second windows without an external state store, nor can they verify resource ownership without an integrated ownership registry.

### 3.2 Ground Truth Leakage
- **Threat:** Detection logic inadvertently referencing ground-truth metadata (e.g., parsing scenario names or attack flags).
- **Mitigation:**
  - Strict data separation: `dataset_telemetry_v1.json` contains zero attack labels, scenario names, or expected outcome fields.
  - Evaluation runs in two distinct, sequential phases: (1) Unlabelled detection execution generating candidate findings, followed by (2) Out-of-band evaluation comparison against the sequestered manifest.

---

## 4. Threats to External Validity

External validity evaluates the extent to which findings generalize beyond the specific testbed.

### 4.1 Architectural Generalizability
- **Threat:** Findings might be specific to Spring Cloud Gateway, Redis Streams, and PostgreSQL.
- **Mitigation:**
  - The contextual activity analysis principles (caller-resource ownership mapping, sliding temporal deques, OpenAPI schema drift tracking) are technology-agnostic.
  - They apply equally to other API gateway architectures (e.g., Kong, Envoy, Apigee, AWS API Gateway) and messaging substrates (e.g., Kafka, RabbitMQ).

### 4.2 API Protocol Specificity (REST vs GraphQL / gRPC)
- **Threat:** The benchmark exclusively evaluates RESTful APIs over HTTP/JSON.
- **Limitation:** GraphQL presents unique attack vectors (e.g., deeply nested recursive queries, batched query IDORs) and gRPC uses HTTP/2 multiplexed streams with Protocol Buffers.
- **Future Work:** Extending Aegis to decode GraphQL ASTs and gRPC Protobuf definitions is identified as a high-priority future research direction.

---

## 5. Threats to Conclusion Validity

Conclusion validity assesses whether the statistical inferences drawn from the data are mathematically defensible.

### 5.1 Temporal Autocorrelation & I.I.D. Assumptions
- **Threat:** Individual HTTP events within a scenario are temporally correlated. Treating them as independent identically distributed (i.i.d.) observations severely underestimates standard errors and inflates $t$-test / z-test significance.
- **Mitigation:**
  - All statistical confidence intervals ($F_1$-score, Precision, Recall) are computed using **scenario-level block bootstrapping** ($B = 500$ resamples).
  - Resampling occurs at the independent scenario level rather than the correlated event level, fully preserving within-scenario autocorrelation.
  - The resulting non-overlapping 95% Bootstrap CIs ([0.4852, 0.6781] vs [0.8132, 0.9218]) provide mathematically rigorous proof of statistical separation.

### 5.2 Correlation vs Causation
- **Threat:** Contextual correlation indicates statistical association between multi-step telemetry patterns and malicious behavior, but does not prove adversarial intent.
- **Mitigation:**
  - This limitation is directly aligned with our **advisory-only response architecture**.
  - Because contextual correlation cannot definitively prove intent, Aegis **never executes autonomous request blocking, token revocation, or customer account suspension**.
  - All findings are surfaced as evidence-backed incidents for human SOC analyst review, preserving human-in-the-loop governance.
