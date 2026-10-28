# Aegis Phase 6.2 — Secure OpenAPI Specification Import Architecture & Implementation

## 1. Executive Summary

Aegis Phase 6.2 introduces secure, persistent OpenAPI specification ingestion and contract parsing for the Aegis Security Operations Center (SOC). While Phase 6.1 captures the *observed* API inventory from passive wire telemetry, Phase 6.2 creates the authoritative *documented* contract inventory by parsing OpenAPI 3.0.x and 3.1.x specifications (JSON and YAML).

The ingestion engine is strictly offline and air-gapped: external `$ref` fetching, remote HTTP lookups, and path traversals are rejected with RFC 7807 ProblemDetail responses. Operations extracted from specifications are mapped into the exact same route templates and service boundaries as the telemetry engine (`RouteNormalizer`), setting the foundation for documented-versus-observed discrepancy detection in Phase 6.3.

---

## 2. Architectural Blueprint

```
                      +------------------------------------------+
                      |    OpenAPI Specification (JSON / YAML)   |
                      +------------------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |     SecuritySpecificationController      |
                      |   - POST /api/v1/security/specs/upload   |
                      |   - ROLE_SECURITY_ADMIN enforced         |
                      |   - Max 5MB file size limit              |
                      +------------------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |             OpenApiParser                |
                      |   - Validates OpenAPI 3.0.x / 3.1.x      |
                      |   - AST complexity limit (50k nodes)     |
                      |   - Safe local $ref resolution only      |
                      |   - Rejects remote URLs & circular refs  |
                      |   - Normalizes routes via RouteNormalizer|
                      +------------------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |       ApiSpecificationService            |
                      |   - Computes SHA-256 content hash        |
                      |   - Idempotent duplicate prevention      |
                      |   - Records actor & metadata             |
                      +------------------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |      security_data.api_specifications    |
                      |      security_data.api_spec_operations  |
                      |   - Flyway V5 migration schema           |
                      |   - Relational cascade deletion          |
                      +------------------------------------------+
                                           |
                                           v
                      +------------------------------------------+
                      |         Angular SOC Dashboard            |
                      |   - OpenAPI Specifications & Operations  |
                      |   - Dropzone file ingestion              |
                      |   - Operations inspection drawer         |
                      |   - Inter Regular (400) typography       |
                      +------------------------------------------+
```

---

## 3. Database Schema (Flyway V5 Migration)

Table definition in `gateway/src/main/resources/db/migration/V5__api_specifications.sql`:

### 3.1 `security_data.api_specifications`
- `id` (UUID PRIMARY KEY)
- `name` (VARCHAR 255 NOT NULL)
- `description` (TEXT)
- `version` (VARCHAR 64 NOT NULL)
- `openapi_version` (VARCHAR 32 NOT NULL)
- `source_filename` (VARCHAR 255 NOT NULL)
- `content_hash` (VARCHAR 64 NOT NULL UNIQUE)
- `raw_content` (TEXT NOT NULL)
- `format` (VARCHAR 16 NOT NULL) — `JSON` or `YAML`
- `status` (VARCHAR 32 NOT NULL DEFAULT 'VALID')
- `imported_at` (TIMESTAMPTZ NOT NULL DEFAULT NOW())
- `imported_by` (VARCHAR 128 NOT NULL)
- `operation_count` (INTEGER NOT NULL DEFAULT 0)
- `path_count` (INTEGER NOT NULL DEFAULT 0)
- `validation_summary` (TEXT)

### 3.2 `security_data.api_spec_operations`
- `id` (UUID PRIMARY KEY)
- `specification_id` (UUID NOT NULL REFERENCES `security_data.api_specifications(id)` ON DELETE CASCADE)
- `http_method` (VARCHAR 16 NOT NULL)
- `path_pattern` (VARCHAR 512 NOT NULL)
- `normalized_route` (VARCHAR 512 NOT NULL)
- `operation_id` (VARCHAR 255)
- `summary` (TEXT)
- `description` (TEXT)
- `tags` (TEXT)
- `deprecated` (BOOLEAN NOT NULL DEFAULT FALSE)
- `service_boundary` (VARCHAR 128 NOT NULL)

---

## 4. Security & Safety Hardening

1. **Strict Offline Processing:**
   - External `$ref` schemas (`http://`, `https://`, file system paths) are rejected with HTTP 400 ProblemDetail.
   - Only safe internal document pointers (e.g. `#/components/schemas/...`) are resolved.
   - Max recursion depth (30) and cycle detection protect against pointer loops.

2. **DoS & Resource Exhaustion Protection:**
   - Max file size: 5 MB.
   - Max parsed JSON/YAML AST nodes: 50,000.
   - Max declared operations per document: 1,000.

3. **Role-Based Access Control:**
   - Ingestion & Deletion: `ROLE_SECURITY_ADMIN`
   - Viewing & Querying: `ROLE_SECURITY_ANALYST` or `ROLE_SECURITY_ADMIN`

4. **Sanitization & Auditability:**
   - Raw uploaded content is preserved for forensic comparison.
   - Sensitive examples or tokens inside specs are never logged to console/log files.
   - SHA-256 hashing guarantees cryptographic idempotency and duplicate detection.

---

## 5. Verification & Test Metrics

### Backend (`gateway`)
- **Unit & Integration Tests:** 19 dedicated tests
  - `OpenApiParserTest` (9 tests): Valid JSON 3.0.3, valid YAML 3.1.0, Swagger 2.0 rejection, 4.x rejection, structural schema validation, remote `$ref` rejection, path traversal rejection, malformed syntax.
  - `SecuritySpecificationControllerTest` (10 tests): RBAC authentication (401), analyst read vs admin write (403), JSON/YAML uploads (201), duplicate upload handling, malformed upload (400), unsupported media type (415), operations extraction, cascading deletion (204).
- **All Gateway Tests:** 187 tests run, 0 failures, 0 errors.

### Frontend (`frontend`)
- **Karma / ChromeHeadless:** 102 tests run, 102 passed, 0 failures.
  - `api-specs.component.spec.ts` (10 tests): Spec catalog display, KPI metrics, drag-and-drop file upload, size/type validation, empty state, error handling, operation drawer slide-in, search filtering, and deletion.
  - `security-api.service.spec.ts`: Specification API contract verification.
- **Production Build:** Angular 18 production build complete (`dist/aegis-frontend`), 0 warnings, 0 errors. Strict Inter Regular (`font-weight: 400`) typography enforced.
