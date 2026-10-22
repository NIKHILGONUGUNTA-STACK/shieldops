package com.aegis.account;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class AccountRepositoryTest {

    @Autowired
    private AccountRepository accountRepository;

    @Autowired
    private DebitRepository debitRepository;

    @Test
    void persistsAccountAndQueriesByCustomerIdAndLocked() {
        UUID accountId = UUID.randomUUID();
        UUID customerId = UUID.randomUUID();
        Account account = new Account(
                accountId, "ACCT-PERSIST-01", customerId, "USD",
                new BigDecimal("5000.0000"), "ACTIVE", Instant.now()
        );
        accountRepository.save(account);

        List<Account> customerAccounts = accountRepository.findByCustomerId(customerId);
        assertEquals(1, customerAccounts.size());
        assertEquals(accountId, customerAccounts.get(0).getId());

        Optional<Account> locked = accountRepository.findLocked(accountId);
        assertTrue(locked.isPresent());
        assertEquals("ACCT-PERSIST-01", locked.get().getAccountNumber());
    }

    @Test
    void persistsDebitRecordAndQueriesByReference() {
        UUID accountId = UUID.randomUUID();
        String ref = "test-debit-ref-001";
        DebitRecord debit = new DebitRecord(ref, accountId, new BigDecimal("100.0000"), "USD");
        debitRepository.save(debit);

        Optional<DebitRecord> found = debitRepository.findByReference(ref);
        assertTrue(found.isPresent());
        assertEquals(ref, found.get().reference);
        assertEquals(accountId, found.get().accountId);
        assertEquals(0, new BigDecimal("100.0000").compareTo(found.get().amount));
    }
}
