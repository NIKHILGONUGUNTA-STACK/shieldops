package com.aegis.transaction;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

class TransactionServiceTest {
    private final BeneficiaryRepository beneficiaries = mock(BeneficiaryRepository.class);
    private final TransactionRepository transactions = mock(TransactionRepository.class);
    private final AccountClient accounts = mock(AccountClient.class);
    private final TransactionService service = new TransactionService(beneficiaries, transactions, accounts);

    @Test
    void successfulTransferExecutesEndToEnd() {
        UUID customerId = UUID.randomUUID();
        UUID sourceAccountId = UUID.randomUUID();
        UUID beneficiaryId = UUID.randomUUID();
        String ref = "transfer-test-success-01";
        BigDecimal amount = new BigDecimal("25.0000");

        Beneficiary beneficiary = new Beneficiary(customerId, "Payee", "DEST-01", "USD");
        beneficiary.verify();
        when(beneficiaries.findById(beneficiaryId)).thenReturn(Optional.of(beneficiary));

        AccountClient.AccountSummary sourceAccount = new AccountClient.AccountSummary(
                sourceAccountId, "ACCT-01", customerId, "USD",
                new BigDecimal("500.0000"), "ACTIVE", Instant.now(), null
        );
        when(accounts.get(sourceAccountId)).thenReturn(sourceAccount);
        when(transactions.findByReference(ref)).thenReturn(Optional.empty());
        when(transactions.save(any(TransactionRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));

        var request = new TransactionController.TransferRequest(
                customerId, sourceAccountId, beneficiaryId, amount, "USD", ref
        );

        TransactionController.TransactionView view = service.transfer(request, null);

        assertNotNull(view);
        assertEquals("COMPLETED", view.status());
        assertEquals(ref, view.reference());
        verify(accounts).debit(sourceAccountId, ref, amount, "USD");
        verify(transactions, atLeast(3)).save(any(TransactionRecord.class));
    }

    @Test
    void idempotentRetryOfPendingTransferReinvokesDebitAndCompletes() {
        UUID customerId = UUID.randomUUID();
        UUID sourceAccountId = UUID.randomUUID();
        UUID beneficiaryId = UUID.randomUUID();
        String ref = "transfer-pending-retry-01";
        BigDecimal amount = new BigDecimal("10.0000");

        TransactionRecord pending = new TransactionRecord(
                ref, customerId, sourceAccountId, beneficiaryId, amount, "USD"
        );
        pending.transition("PENDING");
        when(transactions.findByReference(ref)).thenReturn(Optional.of(pending));
        when(transactions.save(any(TransactionRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));

        var request = new TransactionController.TransferRequest(
                customerId, sourceAccountId, beneficiaryId, amount, "USD", ref
        );

        TransactionController.TransactionView view = service.transfer(request, ref);

        assertEquals("COMPLETED", view.status());
        verify(accounts).debit(sourceAccountId, ref, amount, "USD");
        verifyNoInteractions(beneficiaries);
    }

    @Test
    void idempotentRetryOfAuthorizedTransferAdvancesDirectlyToCompleted() {
        UUID customerId = UUID.randomUUID();
        UUID sourceAccountId = UUID.randomUUID();
        UUID beneficiaryId = UUID.randomUUID();
        String ref = "transfer-auth-retry-01";
        BigDecimal amount = new BigDecimal("15.0000");

        TransactionRecord authorized = new TransactionRecord(
                ref, customerId, sourceAccountId, beneficiaryId, amount, "USD"
        );
        authorized.transition("PENDING");
        authorized.transition("AUTHORIZED");
        when(transactions.findByReference(ref)).thenReturn(Optional.of(authorized));
        when(transactions.save(any(TransactionRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));

        var request = new TransactionController.TransferRequest(
                customerId, sourceAccountId, beneficiaryId, amount, "USD", ref
        );

        TransactionController.TransactionView view = service.transfer(request, ref);

        assertEquals("COMPLETED", view.status());
        verify(accounts, never()).debit(any(), any(), any(), any());
    }

    @Test
    void idempotentRetryOfCompletedTransferReturnsExistingImmediately() {
        UUID customerId = UUID.randomUUID();
        UUID sourceAccountId = UUID.randomUUID();
        UUID beneficiaryId = UUID.randomUUID();
        String ref = "transfer-completed-01";
        BigDecimal amount = new BigDecimal("30.0000");

        TransactionRecord completed = new TransactionRecord(
                ref, customerId, sourceAccountId, beneficiaryId, amount, "USD"
        );
        completed.transition("PENDING");
        completed.transition("AUTHORIZED");
        completed.transition("COMPLETED");
        when(transactions.findByReference(ref)).thenReturn(Optional.of(completed));

        var request = new TransactionController.TransferRequest(
                customerId, sourceAccountId, beneficiaryId, amount, "USD", ref
        );

        TransactionController.TransactionView view = service.transfer(request, ref);

        assertEquals("COMPLETED", view.status());
        verifyNoInteractions(accounts);
        verify(transactions, never()).save(any());
    }

    @Test
    void reusingIdempotencyKeyWithDifferentPayloadThrowsConflict() {
        UUID customerId = UUID.randomUUID();
        UUID sourceAccountId = UUID.randomUUID();
        UUID beneficiaryId = UUID.randomUUID();
        String ref = "key-reused-different";

        TransactionRecord existing = new TransactionRecord(
                ref, customerId, sourceAccountId, beneficiaryId, new BigDecimal("10.0000"), "USD"
        );
        when(transactions.findByReference(ref)).thenReturn(Optional.of(existing));

        // Different amount
        var request = new TransactionController.TransferRequest(
                customerId, sourceAccountId, beneficiaryId, new BigDecimal("20.0000"), "USD", ref
        );

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> service.transfer(request, ref));
        assertEquals(409, ex.getStatusCode().value());
        assertTrue(ex.getReason().contains("already used for a different transfer"));
    }

    @Test
    void transferRejectionByAccountClientMarksFailedAndThrowsConflict() {
        UUID customerId = UUID.randomUUID();
        UUID sourceAccountId = UUID.randomUUID();
        UUID beneficiaryId = UUID.randomUUID();
        String ref = "transfer-rejected-01";
        BigDecimal amount = new BigDecimal("50.0000");

        Beneficiary beneficiary = new Beneficiary(customerId, "Payee", "DEST-01", "USD");
        beneficiary.verify();
        when(beneficiaries.findById(beneficiaryId)).thenReturn(Optional.of(beneficiary));

        AccountClient.AccountSummary sourceAccount = new AccountClient.AccountSummary(
                sourceAccountId, "ACCT-01", customerId, "USD",
                new BigDecimal("500.0000"), "ACTIVE", Instant.now(), null
        );
        when(accounts.get(sourceAccountId)).thenReturn(sourceAccount);
        when(transactions.findByReference(ref)).thenReturn(Optional.empty());
        when(transactions.save(any(TransactionRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));

        doThrow(HttpClientErrorException.create(HttpStatus.CONFLICT, "Rejected", HttpHeaders.EMPTY, new byte[0], null))
                .when(accounts).debit(sourceAccountId, ref, amount, "USD");

        var request = new TransactionController.TransferRequest(
                customerId, sourceAccountId, beneficiaryId, amount, "USD", ref
        );

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> service.transfer(request, ref));
        assertEquals(409, ex.getStatusCode().value());
    }

    @Test
    void transferAccountServiceUnavailableLeavesPendingAndThrowsBadGateway() {
        UUID customerId = UUID.randomUUID();
        UUID sourceAccountId = UUID.randomUUID();
        UUID beneficiaryId = UUID.randomUUID();
        String ref = "transfer-unavailable-01";
        BigDecimal amount = new BigDecimal("50.0000");

        Beneficiary beneficiary = new Beneficiary(customerId, "Payee", "DEST-01", "USD");
        beneficiary.verify();
        when(beneficiaries.findById(beneficiaryId)).thenReturn(Optional.of(beneficiary));

        AccountClient.AccountSummary sourceAccount = new AccountClient.AccountSummary(
                sourceAccountId, "ACCT-01", customerId, "USD",
                new BigDecimal("500.0000"), "ACTIVE", Instant.now(), null
        );
        when(accounts.get(sourceAccountId)).thenReturn(sourceAccount);
        when(transactions.findByReference(ref)).thenReturn(Optional.empty());
        when(transactions.save(any(TransactionRecord.class))).thenAnswer(invocation -> invocation.getArgument(0));

        doThrow(new ResourceAccessException("Connection refused"))
                .when(accounts).debit(sourceAccountId, ref, amount, "USD");

        var request = new TransactionController.TransferRequest(
                customerId, sourceAccountId, beneficiaryId, amount, "USD", ref
        );

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> service.transfer(request, ref));
        assertEquals(502, ex.getStatusCode().value());
        assertTrue(ex.getReason().contains("transfer can be retried safely"));
    }

    @Test
    void transferThrowsForbiddenWhenBeneficiaryBelongsToDifferentCustomer() {
        UUID customerId = UUID.randomUUID();
        UUID otherCustomer = UUID.randomUUID();
        UUID beneficiaryId = UUID.randomUUID();

        Beneficiary beneficiary = new Beneficiary(otherCustomer, "Payee", "DEST-01", "USD");
        beneficiary.verify();
        when(beneficiaries.findById(beneficiaryId)).thenReturn(Optional.of(beneficiary));

        var request = new TransactionController.TransferRequest(
                customerId, UUID.randomUUID(), beneficiaryId, new BigDecimal("10.0000"), "USD", "ref-cust-diff"
        );

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> service.transfer(request, null));
        assertEquals(403, ex.getStatusCode().value());
    }

    @Test
    void transferThrowsConflictWhenSourceAccountHasInsufficientBalance() {
        UUID customerId = UUID.randomUUID();
        UUID sourceAccountId = UUID.randomUUID();
        UUID beneficiaryId = UUID.randomUUID();

        Beneficiary beneficiary = new Beneficiary(customerId, "Payee", "DEST-01", "USD");
        beneficiary.verify();
        when(beneficiaries.findById(beneficiaryId)).thenReturn(Optional.of(beneficiary));

        AccountClient.AccountSummary sourceAccount = new AccountClient.AccountSummary(
                sourceAccountId, "ACCT-01", customerId, "USD",
                new BigDecimal("5.0000"), "ACTIVE", Instant.now(), null
        );
        when(accounts.get(sourceAccountId)).thenReturn(sourceAccount);

        var request = new TransactionController.TransferRequest(
                customerId, sourceAccountId, beneficiaryId, new BigDecimal("100.0000"), "USD", "ref-low-bal"
        );

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> service.transfer(request, null));
        assertEquals(409, ex.getStatusCode().value());
        assertTrue(ex.getReason().contains("Insufficient available balance"));
    }

    @Test
    void beneficiaryLifecycleCreateAndVerify() {
        UUID customerId = UUID.randomUUID();
        when(beneficiaries.save(any(Beneficiary.class))).thenAnswer(invocation -> invocation.getArgument(0));

        var createReq = new TransactionController.CreateBeneficiary(
                customerId, "New Payee", "DEST-001", "USD"
        );
        var created = service.createBeneficiary(createReq);
        assertEquals("PENDING", created.status());

        Beneficiary beneficiary = new Beneficiary(customerId, "New Payee", "DEST-001", "USD");
        when(beneficiaries.findById(created.id())).thenReturn(Optional.of(beneficiary));

        var verified = service.verifyBeneficiary(created.id());
        assertEquals("VERIFIED", verified.status());

        // Second verification should throw Conflict
        assertThrows(ResponseStatusException.class, () -> service.verifyBeneficiary(created.id()));
    }
}
