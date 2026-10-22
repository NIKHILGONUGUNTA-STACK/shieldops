package com.aegis.transaction;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.math.BigDecimal;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class TransactionRepositoryTest {

    @Autowired
    private BeneficiaryRepository beneficiaryRepository;

    @Autowired
    private TransactionRepository transactionRepository;

    @Test
    void persistsBeneficiaryAndQueriesByCustomerId() {
        UUID customerId = UUID.randomUUID();
        Beneficiary beneficiary = new Beneficiary(
                customerId, "Test Beneficiary", "SYNTH-DEST-001", "USD"
        );
        beneficiaryRepository.save(beneficiary);

        List<Beneficiary> found = beneficiaryRepository.findByCustomerId(customerId);
        assertEquals(1, found.size());
        assertEquals("Test Beneficiary", found.get(0).getName());
        assertEquals("PENDING", found.get(0).getStatus());
    }

    @Test
    void persistsTransactionAndQueriesByReferenceAndCustomer() {
        UUID customerId = UUID.randomUUID();
        UUID sourceAccountId = UUID.randomUUID();
        Beneficiary beneficiary = beneficiaryRepository.save(new Beneficiary(
                customerId, "Payee", "DEST-01", "USD"
        ));

        String ref = "transfer-repo-test-01";
        TransactionRecord record = new TransactionRecord(
                ref, customerId, sourceAccountId, beneficiary.getId(),
                new BigDecimal("50.0000"), "USD"
        );
        transactionRepository.save(record);

        Optional<TransactionRecord> byRef = transactionRepository.findByReference(ref);
        assertTrue(byRef.isPresent());
        assertEquals(customerId, byRef.get().getCustomerId());
        assertEquals("CREATED", byRef.get().getStatus());

        List<TransactionRecord> byCustomer = transactionRepository.findByCustomerId(customerId);
        assertEquals(1, byCustomer.size());
    }
}
