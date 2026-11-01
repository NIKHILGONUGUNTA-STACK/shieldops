package com.aegis.gateway.specs;

import com.aegis.gateway.specs.dto.ApiSpecificationResponse;
import com.aegis.gateway.specs.dto.DeclaredOperationResponse;
import com.aegis.gateway.specs.dto.OperationChange;
import com.aegis.gateway.specs.dto.SpecificationDiffResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.*;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class SpecificationEvolutionTest {

    @Mock
    private OpenApiParser parser;

    @Mock
    private ApiSpecificationRepository repository;

    private ApiSpecificationService service;

    private final UUID baseSpecId = UUID.randomUUID();
    private final UUID targetSpecId = UUID.randomUUID();
    private final Instant now = Instant.now();

    @BeforeEach
    void setUp() {
        service = new ApiSpecificationService(parser, repository);
    }

    @Test
    @DisplayName("importSpecification auto-increments revisionNumber when spec with same title exists")
    void testImportSpecificationIncrementsRevision() {
        byte[] content = "openapi: 3.0.3\ninfo:\n  title: Customer API\n  version: 2.0.0".getBytes();
        var specData = new OpenApiSpecData(
            "Customer API", "Description", "2.0.0", "3.0.3",
            "YAML", "hash_new_content_12345", 5, 3, "Valid",
            List.of()
        );

        when(parser.parseAndValidate(any(), any())).thenReturn(specData);
        when(repository.findByContentHash("hash_new_content_12345")).thenReturn(Optional.empty());
        when(repository.findNextRevisionNumberByName("Customer API")).thenReturn(2);
        when(repository.findOperationsBySpecId(any())).thenReturn(List.of());

        ApiSpecificationResponse imported = service.importSpecification(content, "customer-v2.yaml", "sec-admin");

        assertThat(imported.name()).isEqualTo("Customer API");
        assertThat(imported.version()).isEqualTo("2.0.0");
        assertThat(imported.revisionNumber()).isEqualTo(2);
        verify(repository).save(argThat(spec -> spec.revisionNumber() == 2), any(), any());
    }

    @Test
    @DisplayName("importSpecification detects duplicate content hash and returns existing without incrementing")
    void testImportSpecificationDetectsDuplicate() {
        byte[] content = "openapi: 3.0.3\ninfo:\n  title: Customer API\n  version: 1.0.0".getBytes();
        var specData = new OpenApiSpecData(
            "Customer API", "Description", "1.0.0", "3.0.3",
            "YAML", "hash_existing_content_abc", 5, 3, "Valid",
            List.of()
        );

        var existingSpec = new ApiSpecificationResponse(
            baseSpecId, "Customer API", "Description", "1.0.0", 1, "3.0.3",
            "customer-v1.yaml", "hash_existing_content_abc", "YAML", "ACTIVE",
            now, "admin", 5, 3, "Valid", List.of()
        );

        when(parser.parseAndValidate(any(), any())).thenReturn(specData);
        when(repository.findByContentHash("hash_existing_content_abc")).thenReturn(Optional.of(existingSpec));
        when(repository.findOperationsBySpecId(baseSpecId)).thenReturn(List.of());

        ApiSpecificationResponse result = service.importSpecification(content, "customer-v1.yaml", "sec-admin");

        assertThat(result.id()).isEqualTo(baseSpecId);
        assertThat(result.revisionNumber()).isEqualTo(1);
        verify(repository, never()).save(any(), any(), any());
    }

    @Test
    @DisplayName("getSpecificationRevisions lists all revisions of specification family ordered descending")
    void testGetSpecificationRevisions() {
        var spec = new ApiSpecificationResponse(
            baseSpecId, "Customer API", "Description", "1.0.0", 1, "3.0.3",
            "customer.yaml", "hash1", "YAML", "ACTIVE",
            now, "admin", 5, 3, "Valid", List.of()
        );
        var rev2 = new ApiSpecificationResponse(
            targetSpecId, "Customer API", "Updated", "2.0.0", 2, "3.0.3",
            "customer.yaml", "hash2", "YAML", "ACTIVE",
            now.plusSeconds(3600), "admin", 7, 4, "Valid", List.of()
        );

        when(repository.findById(baseSpecId)).thenReturn(Optional.of(spec));
        when(repository.findRevisionsByName("Customer API")).thenReturn(List.of(rev2, spec));

        List<ApiSpecificationResponse> revisions = service.getSpecificationRevisions(baseSpecId);

        assertThat(revisions).hasSize(2);
        assertThat(revisions.get(0).revisionNumber()).isEqualTo(2);
        assertThat(revisions.get(1).revisionNumber()).isEqualTo(1);
    }

    @Test
    @DisplayName("compareSpecifications detects added, removed, modified, and unchanged operations")
    void testCompareSpecificationsStructuralDiff() {
        var baseSpec = new ApiSpecificationResponse(
            baseSpecId, "Customer API", "Base", "1.0.0", 1, "3.0.3",
            "base.yaml", "hash1", "YAML", "ACTIVE", now, "admin", 3, 2, "Valid", List.of()
        );
        var targetSpec = new ApiSpecificationResponse(
            targetSpecId, "Customer API", "Target", "2.0.0", 2, "3.0.3",
            "target.yaml", "hash2", "YAML", "ACTIVE", now, "admin", 3, 2, "Valid", List.of()
        );

        when(repository.findById(baseSpecId)).thenReturn(Optional.of(baseSpec));
        when(repository.findById(targetSpecId)).thenReturn(Optional.of(targetSpec));

        // Base operations:
        // 1. GET /api/v1/customers (UNCHANGED)
        // 2. POST /api/v1/customers (MODIFIED - summary & tags changed)
        // 3. DELETE /api/v1/customers/{id} (REMOVED in target)
        var op1Base = new DeclaredOperationResponse(
            UUID.randomUUID(), baseSpecId, "GET", "/api/v1/customers", "/api/v1/customers",
            "listCustomers", "List all customers", "Desc", "customer", false, "customer-service"
        );
        var op2Base = new DeclaredOperationResponse(
            UUID.randomUUID(), baseSpecId, "POST", "/api/v1/customers", "/api/v1/customers",
            "createCustomer", "Create customer", "Desc", "customer", false, "customer-service"
        );
        var op3Base = new DeclaredOperationResponse(
            UUID.randomUUID(), baseSpecId, "DELETE", "/api/v1/customers/{id}", "/api/v1/customers/{id}",
            "deleteCustomer", "Delete customer", "Desc", "customer", false, "customer-service"
        );
        when(repository.findOperationsBySpecId(baseSpecId)).thenReturn(List.of(op1Base, op2Base, op3Base));

        // Target operations:
        // 1. GET /api/v1/customers (UNCHANGED)
        // 2. POST /api/v1/customers (MODIFIED - summary changed to 'Create customer profile', tags 'customer, v2', deprecated true)
        // 3. GET /api/v1/customers/{id}/profile (ADDED in target)
        var op1Target = new DeclaredOperationResponse(
            UUID.randomUUID(), targetSpecId, "GET", "/api/v1/customers", "/api/v1/customers",
            "listCustomers", "List all customers", "Desc", "customer", false, "customer-service"
        );
        var op2Target = new DeclaredOperationResponse(
            UUID.randomUUID(), targetSpecId, "POST", "/api/v1/customers", "/api/v1/customers",
            "createCustomer", "Create customer profile", "Desc", "customer, v2", true, "customer-service"
        );
        var op4Target = new DeclaredOperationResponse(
            UUID.randomUUID(), targetSpecId, "GET", "/api/v1/customers/{id}/profile", "/api/v1/customers/{id}/profile",
            "getProfile", "Get profile", "Desc", "customer", false, "customer-service"
        );
        when(repository.findOperationsBySpecId(targetSpecId)).thenReturn(List.of(op1Target, op2Target, op4Target));

        SpecificationDiffResponse diff = service.compareSpecifications(baseSpecId, targetSpecId);

        assertThat(diff.addedCount()).isEqualTo(1);
        assertThat(diff.removedCount()).isEqualTo(1);
        assertThat(diff.modifiedCount()).isEqualTo(1);
        assertThat(diff.unchangedCount()).isEqualTo(1);

        // Verify changes list
        assertThat(diff.changes()).hasSize(4);

        OperationChange added = diff.changes().stream().filter(c -> "ADDED".equals(c.changeType())).findFirst().orElseThrow();
        assertThat(added.normalizedRoute()).isEqualTo("/api/v1/customers/{id}/profile");

        OperationChange removed = diff.changes().stream().filter(c -> "REMOVED".equals(c.changeType())).findFirst().orElseThrow();
        assertThat(removed.normalizedRoute()).isEqualTo("/api/v1/customers/{id}");

        OperationChange modified = diff.changes().stream().filter(c -> "MODIFIED".equals(c.changeType())).findFirst().orElseThrow();
        assertThat(modified.normalizedRoute()).isEqualTo("/api/v1/customers");
        assertThat(modified.diffDetails()).isNotEmpty();
        assertThat(modified.diffDetails().stream().anyMatch(d -> d.contains("summary updated"))).isTrue();
        assertThat(modified.diffDetails().stream().anyMatch(d -> d.contains("Deprecated status changed"))).isTrue();

        OperationChange unchanged = diff.changes().stream().filter(c -> "UNCHANGED".equals(c.changeType())).findFirst().orElseThrow();
        assertThat(unchanged.normalizedRoute()).isEqualTo("/api/v1/customers");
        assertThat(unchanged.diffDetails()).isEmpty();
    }

    @Test
    @DisplayName("compareSpecifications against itself produces zero modifications, additions, or removals")
    void testCompareSpecificationsSelfDiff() {
        var spec = new ApiSpecificationResponse(
            baseSpecId, "Customer API", "Base", "1.0.0", 1, "3.0.3",
            "base.yaml", "hash1", "YAML", "ACTIVE", now, "admin", 1, 1, "Valid", List.of()
        );
        var op = new DeclaredOperationResponse(
            UUID.randomUUID(), baseSpecId, "GET", "/api/v1/customers", "/api/v1/customers",
            "listCustomers", "List customers", "Desc", "customer", false, "customer-service"
        );

        when(repository.findById(baseSpecId)).thenReturn(Optional.of(spec));
        when(repository.findOperationsBySpecId(baseSpecId)).thenReturn(List.of(op));

        SpecificationDiffResponse diff = service.compareSpecifications(baseSpecId, baseSpecId);

        assertThat(diff.addedCount()).isEqualTo(0);
        assertThat(diff.removedCount()).isEqualTo(0);
        assertThat(diff.modifiedCount()).isEqualTo(0);
        assertThat(diff.unchangedCount()).isEqualTo(1);
    }
}
