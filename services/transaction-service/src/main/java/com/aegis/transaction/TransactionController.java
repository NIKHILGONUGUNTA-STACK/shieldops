package com.aegis.transaction;

import com.aegis.transaction.security.TrustTokenUtils;
import jakarta.validation.Valid;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;

@RestController
public class TransactionController {
    private final TransactionService transactionService;

    public TransactionController(TransactionService transactionService) {
        this.transactionService = transactionService;
    }

    @GetMapping("/beneficiaries")
    public List<BeneficiaryView> beneficiaries(
            @RequestParam(name = "customerId", required = false) UUID customerId,
            @RequestHeader(value = TrustTokenUtils.CUSTOMER_ID_HEADER, required = false) String callerCustomerId,
            @RequestHeader(value = TrustTokenUtils.ROLES_HEADER, required = false) String callerRoles) {
        customerId = resolveCustomerId(customerId, callerCustomerId, callerRoles);
        return transactionService.listBeneficiaries(customerId);
    }

    @PostMapping("/beneficiaries")
    @ResponseStatus(HttpStatus.CREATED)
    public BeneficiaryView create(
            @Valid @RequestBody CreateBeneficiary request,
            @RequestHeader(value = TrustTokenUtils.CUSTOMER_ID_HEADER, required = false) String callerCustomerId,
            @RequestHeader(value = TrustTokenUtils.ROLES_HEADER, required = false) String callerRoles) {
        verifyCustomerOwnership(request.customerId(), callerCustomerId, callerRoles);
        return transactionService.createBeneficiary(request);
    }

    @GetMapping("/beneficiaries/{id}")
    public BeneficiaryView beneficiary(
            @PathVariable("id") UUID id,
            @RequestHeader(value = TrustTokenUtils.CUSTOMER_ID_HEADER, required = false) String callerCustomerId,
            @RequestHeader(value = TrustTokenUtils.ROLES_HEADER, required = false) String callerRoles) {
        BeneficiaryView b = transactionService.getBeneficiaryView(id);
        verifyCustomerOwnership(b.customerId(), callerCustomerId, callerRoles);
        return b;
    }

    @PostMapping("/beneficiaries/{id}/verify")
    public BeneficiaryView verify(
            @PathVariable("id") UUID id,
            @RequestHeader(value = TrustTokenUtils.CUSTOMER_ID_HEADER, required = false) String callerCustomerId,
            @RequestHeader(value = TrustTokenUtils.ROLES_HEADER, required = false) String callerRoles) {
        BeneficiaryView b = transactionService.getBeneficiaryView(id);
        verifyCustomerOwnership(b.customerId(), callerCustomerId, callerRoles);
        return transactionService.verifyBeneficiary(id);
    }

    @GetMapping("/transactions")
    public List<TransactionView> transactions(
            @RequestParam(name = "customerId", required = false) UUID customerId,
            @RequestHeader(value = TrustTokenUtils.CUSTOMER_ID_HEADER, required = false) String callerCustomerId,
            @RequestHeader(value = TrustTokenUtils.ROLES_HEADER, required = false) String callerRoles) {
        customerId = resolveCustomerId(customerId, callerCustomerId, callerRoles);
        return transactionService.listTransactions(customerId);
    }

    @GetMapping("/transactions/{id}")
    public TransactionView transaction(
            @PathVariable("id") UUID id,
            @RequestHeader(value = TrustTokenUtils.CUSTOMER_ID_HEADER, required = false) String callerCustomerId,
            @RequestHeader(value = TrustTokenUtils.ROLES_HEADER, required = false) String callerRoles) {
        TransactionView t = transactionService.getTransaction(id);
        verifyCustomerOwnership(t.customerId(), callerCustomerId, callerRoles);
        return t;
    }

    @PostMapping("/transfers")
    @ResponseStatus(HttpStatus.CREATED)
    public TransactionView transfer(
            @Valid @RequestBody TransferRequest request,
            @RequestHeader(value = "Idempotency-Key", required = false) String key,
            @RequestHeader(value = TrustTokenUtils.CUSTOMER_ID_HEADER, required = false) String callerCustomerId,
            @RequestHeader(value = TrustTokenUtils.ROLES_HEADER, required = false) String callerRoles) {
        verifyCustomerOwnership(request.customerId(), callerCustomerId, callerRoles);
        return transactionService.transfer(request, key);
    }

    private UUID resolveCustomerId(UUID customerId, String callerCustomerId, String callerRoles) {
        boolean isPrivileged = callerRoles != null && (callerRoles.contains("SECURITY_ADMIN") || callerRoles.contains("SECURITY_ANALYST"));
        if (!isPrivileged && callerCustomerId != null && !callerCustomerId.isBlank()) {
            try {
                UUID callerUuid = UUID.fromString(callerCustomerId.trim());
                if (customerId != null && !customerId.equals(callerUuid)) {
                    throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access to another customer's resources is forbidden");
                }
                return callerUuid;
            } catch (IllegalArgumentException e) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid customer context");
            }
        }
        return customerId;
    }

    private void verifyCustomerOwnership(UUID resourceCustomerId, String callerCustomerId, String callerRoles) {
        boolean isPrivileged = callerRoles != null && (callerRoles.contains("SECURITY_ADMIN") || callerRoles.contains("SECURITY_ANALYST"));
        if (isPrivileged) {
            return;
        }
        if (callerCustomerId != null && !callerCustomerId.isBlank()) {
            try {
                UUID callerUuid = UUID.fromString(callerCustomerId.trim());
                if (!callerUuid.equals(resourceCustomerId)) {
                    throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Operation on another customer's resource is forbidden");
                }
            } catch (IllegalArgumentException e) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid customer context");
            }
        }
    }

    public record CreateBeneficiary(@NotNull UUID customerId,
                                   @NotBlank @jakarta.validation.constraints.Size(max = 80) String name,
                                   @NotBlank @jakarta.validation.constraints.Size(max = 34) String destinationAccountReference,
                                   @NotNull @Pattern(regexp = "[A-Z]{3}") String currency) {}

    public record BeneficiaryView(UUID id, UUID customerId, String name, String destinationAccountReference,
                                  String currency, String status, java.time.Instant createdAt) {
        static BeneficiaryView from(Beneficiary b) {
            return new BeneficiaryView(b.getId(), b.getCustomerId(), b.getName(), b.getDestinationAccountReference(), b.getCurrency(), b.getStatus(), b.getCreatedAt());
        }
    }

    public record TransactionView(UUID id, String reference, UUID customerId, UUID sourceAccountId,
                                  UUID beneficiaryId, BigDecimal amount, String currency, String status,
                                  java.time.Instant createdAt, java.time.Instant updatedAt) {
        static TransactionView from(TransactionRecord t) {
            return new TransactionView(t.getId(), t.getReference(), t.getCustomerId(), t.getSourceAccountId(), t.getBeneficiaryId(), t.getAmount(), t.getCurrency(), t.getStatus(), t.getCreatedAt(), t.getUpdatedAt());
        }
    }

    public record TransferRequest(@NotNull UUID customerId,
                                  @NotNull UUID sourceAccountId,
                                  @NotNull UUID beneficiaryId,
                                  @NotNull @DecimalMin(value = "0.0001") @jakarta.validation.constraints.Digits(integer = 15, fraction = 4) BigDecimal amount,
                                  @NotNull @Pattern(regexp = "[A-Z]{3}") String currency,
                                  @jakarta.validation.constraints.Size(max = 80) String reference) {}
}
