package com.aegis.transaction;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;
import java.math.BigDecimal;
import java.util.Optional;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class TransferValidationTest {
    private final BeneficiaryRepository beneficiaries = mock(BeneficiaryRepository.class);
    private final TransactionRepository transactions = mock(TransactionRepository.class);
    private final AccountClient accounts = mock(AccountClient.class);
    private final TransactionService service = new TransactionService(beneficiaries, transactions, accounts);

    @Test
    void pendingBeneficiaryCannotBeUsedForTransfer() {
        UUID customer = UUID.randomUUID(), beneficiaryId = UUID.randomUUID();
        when(beneficiaries.findById(beneficiaryId)).thenReturn(Optional.of(new Beneficiary(customer, "Synthetic Payee", "EXT-1", "USD")));
        var request = new TransactionController.TransferRequest(customer, UUID.randomUUID(), beneficiaryId, new BigDecimal("1.0000"), "USD", "ref-1");
        var error = assertThrows(ResponseStatusException.class, () -> service.transfer(request, null));
        assertEquals(409, error.getStatusCode().value());
        verifyNoInteractions(accounts);
        verify(transactions, never()).save(any());
    }
}
