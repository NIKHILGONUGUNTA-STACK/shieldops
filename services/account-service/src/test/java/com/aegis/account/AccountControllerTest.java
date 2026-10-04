package com.aegis.account;

import org.junit.jupiter.api.Test;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.Optional;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class AccountControllerTest {
    @Test void accountDetailComposesItsOwnerProfile() {
        UUID accountId=UUID.randomUUID(), customerId=UUID.randomUUID();
        AccountRepository repository=mock(AccountRepository.class);
        CustomerClient customers=mock(CustomerClient.class);
        Account account=mock(Account.class);
        when(repository.findById(accountId)).thenReturn(Optional.of(account));
        when(account.getId()).thenReturn(accountId);
        when(account.getAccountNumber()).thenReturn("ACCT-TEST-01");
        when(account.getCustomerId()).thenReturn(customerId);
        when(account.getCurrency()).thenReturn("USD");
        when(account.getBalance()).thenReturn(new BigDecimal("50.2500"));
        when(account.getStatus()).thenReturn("ACTIVE");
        when(account.getOpenedAt()).thenReturn(Instant.parse("2025-01-01T00:00:00Z"));
        var owner=new CustomerClient.CustomerSummary(customerId,"CUST-TEST-01","Casey","Example","casey@example.test","US","ACTIVE");
        when(customers.get(customerId)).thenReturn(owner);

        var detail=new AccountController(repository,customers,mock(AccountDebitService.class)).get(accountId);
        assertEquals(accountId,detail.id());
        assertEquals(customerId,detail.customerId());
        assertEquals("50.2500",detail.balance().toPlainString());
        assertEquals("CUST-TEST-01",detail.customer().customerNumber());
    }
}
