package com.aegis.account;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AccountDebitServiceTest {

    @Test
    void successfulDebitReducesBalanceAndCreatesDebitRecord() {
        var accounts = mock(AccountRepository.class);
        var ledger = mock(DebitRepository.class);
        UUID id = UUID.randomUUID();
        String reference = "transfer-success-01";
        BigDecimal initialBalance = new BigDecimal("100.0000");
        BigDecimal debitAmount = new BigDecimal("25.5000");

        Account account = new Account(id, "ACCT-01", UUID.randomUUID(), "USD", initialBalance, "ACTIVE", Instant.now());
        when(ledger.findByReference(reference)).thenReturn(Optional.empty());
        when(accounts.findLocked(id)).thenReturn(Optional.of(account));

        var service = new AccountDebitService(accounts, ledger);
        var receipt = service.debit(id, reference, debitAmount, "USD");

        assertEquals(reference, receipt.reference());
        assertEquals(0, new BigDecimal("74.5000").compareTo(account.getBalance()));
        verify(ledger).save(any(DebitRecord.class));
    }

    @Test
    void referenceRetryReturnsPriorDebitWithoutChangingBalanceAgain() {
        var accounts = mock(AccountRepository.class);
        var ledger = mock(DebitRepository.class);
        UUID id = UUID.randomUUID();
        String reference = "transfer-1";
        var prior = new DebitRecord(reference, id, new BigDecimal("3.2500"), "USD");
        when(ledger.findByReference(reference)).thenReturn(Optional.of(prior));

        var service = new AccountDebitService(accounts, ledger);
        var receipt = service.debit(id, reference, new BigDecimal("3.2500"), "USD");

        assertEquals(reference, receipt.reference());
        verifyNoInteractions(accounts);
        verify(ledger, never()).save(any());
    }

    @Test
    void referenceCannotBeReusedForDifferentAmount() {
        var accounts = mock(AccountRepository.class);
        var ledger = mock(DebitRepository.class);
        UUID id = UUID.randomUUID();
        when(ledger.findByReference("transfer-1")).thenReturn(Optional.of(new DebitRecord("transfer-1", id, new BigDecimal("3.2500"), "USD")));

        var service = new AccountDebitService(accounts, ledger);
        var error = assertThrows(ResponseStatusException.class, () -> service.debit(id, "transfer-1", new BigDecimal("4.0000"), "USD"));
        assertEquals(409, error.getStatusCode().value());
        verifyNoInteractions(accounts);
    }

    @Test
    void referenceCannotBeReusedForDifferentCurrency() {
        var accounts = mock(AccountRepository.class);
        var ledger = mock(DebitRepository.class);
        UUID id = UUID.randomUUID();
        when(ledger.findByReference("transfer-1")).thenReturn(Optional.of(new DebitRecord("transfer-1", id, new BigDecimal("3.2500"), "USD")));

        var service = new AccountDebitService(accounts, ledger);
        var error = assertThrows(ResponseStatusException.class, () -> service.debit(id, "transfer-1", new BigDecimal("3.2500"), "EUR"));
        assertEquals(409, error.getStatusCode().value());
        verifyNoInteractions(accounts);
    }

    @Test
    void debitThrowsNotFoundWhenAccountDoesNotExist() {
        var accounts = mock(AccountRepository.class);
        var ledger = mock(DebitRepository.class);
        UUID id = UUID.randomUUID();
        when(ledger.findByReference("ref-missing")).thenReturn(Optional.empty());
        when(accounts.findLocked(id)).thenReturn(Optional.empty());

        var service = new AccountDebitService(accounts, ledger);
        var error = assertThrows(ResponseStatusException.class, () -> service.debit(id, "ref-missing", new BigDecimal("10.0000"), "USD"));
        assertEquals(404, error.getStatusCode().value());
    }

    @Test
    void debitThrowsConflictWhenAccountIsNotActive() {
        var accounts = mock(AccountRepository.class);
        var ledger = mock(DebitRepository.class);
        UUID id = UUID.randomUUID();
        Account blockedAccount = new Account(id, "ACCT-02", UUID.randomUUID(), "USD", new BigDecimal("100.0000"), "BLOCKED", Instant.now());
        when(ledger.findByReference("ref-blocked")).thenReturn(Optional.empty());
        when(accounts.findLocked(id)).thenReturn(Optional.of(blockedAccount));

        var service = new AccountDebitService(accounts, ledger);
        var error = assertThrows(ResponseStatusException.class, () -> service.debit(id, "ref-blocked", new BigDecimal("10.0000"), "USD"));
        assertEquals(409, error.getStatusCode().value());
    }

    @Test
    void debitThrowsConflictOnCurrencyMismatch() {
        var accounts = mock(AccountRepository.class);
        var ledger = mock(DebitRepository.class);
        UUID id = UUID.randomUUID();
        Account account = new Account(id, "ACCT-03", UUID.randomUUID(), "GBP", new BigDecimal("100.0000"), "ACTIVE", Instant.now());
        when(ledger.findByReference("ref-cur")).thenReturn(Optional.empty());
        when(accounts.findLocked(id)).thenReturn(Optional.of(account));

        var service = new AccountDebitService(accounts, ledger);
        var error = assertThrows(ResponseStatusException.class, () -> service.debit(id, "ref-cur", new BigDecimal("10.0000"), "USD"));
        assertEquals(409, error.getStatusCode().value());
    }

    @Test
    void debitThrowsConflictOnInsufficientBalance() {
        var accounts = mock(AccountRepository.class);
        var ledger = mock(DebitRepository.class);
        UUID id = UUID.randomUUID();
        Account account = new Account(id, "ACCT-04", UUID.randomUUID(), "USD", new BigDecimal("5.0000"), "ACTIVE", Instant.now());
        when(ledger.findByReference("ref-insufficient")).thenReturn(Optional.empty());
        when(accounts.findLocked(id)).thenReturn(Optional.of(account));

        var service = new AccountDebitService(accounts, ledger);
        var error = assertThrows(ResponseStatusException.class, () -> service.debit(id, "ref-insufficient", new BigDecimal("10.0000"), "USD"));
        assertEquals(409, error.getStatusCode().value());
    }
}
