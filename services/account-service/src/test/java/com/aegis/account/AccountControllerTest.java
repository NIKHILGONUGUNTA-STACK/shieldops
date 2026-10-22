package com.aegis.account;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.server.ResponseStatusException;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(AccountController.class)
@Import(ApiExceptionHandler.class)
class AccountControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private AccountRepository accountRepository;

    @MockitoBean
    private CustomerClient customerClient;

    @MockitoBean
    private AccountDebitService debitService;

    @Test
    void listReturnsAccounts() throws Exception {
        UUID accountId = UUID.randomUUID();
        UUID customerId = UUID.randomUUID();
        Account account = new Account(accountId, "ACCT-01", customerId, "USD", new BigDecimal("100.0000"), "ACTIVE", Instant.now());
        when(accountRepository.findAll()).thenReturn(List.of(account));

        mockMvc.perform(get("/accounts"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(accountId.toString()))
                .andExpect(jsonPath("$[0].accountNumber").value("ACCT-01"))
                .andExpect(jsonPath("$[0].currency").value("USD"));
    }

    @Test
    void listWithCustomerIdFiltersAccounts() throws Exception {
        UUID accountId = UUID.randomUUID();
        UUID customerId = UUID.randomUUID();
        Account account = new Account(accountId, "ACCT-02", customerId, "USD", new BigDecimal("200.0000"), "ACTIVE", Instant.now());
        when(accountRepository.findByCustomerId(customerId)).thenReturn(List.of(account));

        mockMvc.perform(get("/accounts?customerId={customerId}", customerId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(accountId.toString()))
                .andExpect(jsonPath("$[0].customerId").value(customerId.toString()));
    }

    @Test
    void accountDetailComposesOwnerProfile() throws Exception {
        UUID accountId = UUID.randomUUID();
        UUID customerId = UUID.randomUUID();
        Account account = new Account(accountId, "ACCT-TEST-01", customerId, "USD", new BigDecimal("50.2500"), "ACTIVE", Instant.parse("2025-01-01T00:00:00Z"));
        when(accountRepository.findById(accountId)).thenReturn(Optional.of(account));
        CustomerClient.CustomerSummary owner = new CustomerClient.CustomerSummary(
                customerId, "CUST-TEST-01", "Casey", "Example", "casey@example.test", "US", "ACTIVE"
        );
        when(customerClient.get(customerId)).thenReturn(owner);

        mockMvc.perform(get("/accounts/{id}", accountId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(accountId.toString()))
                .andExpect(jsonPath("$.accountNumber").value("ACCT-TEST-01"))
                .andExpect(jsonPath("$.balance").value(50.2500))
                .andExpect(jsonPath("$.customer.customerNumber").value("CUST-TEST-01"));
    }

    @Test
    void accountDetailReturnsNotFoundWhenMissing() throws Exception {
        UUID accountId = UUID.randomUUID();
        when(accountRepository.findById(accountId)).thenReturn(Optional.empty());

        mockMvc.perform(get("/accounts/{id}", accountId))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.detail").value("Account not found"));
    }

    @Test
    void balanceReturnsAvailableBalance() throws Exception {
        UUID accountId = UUID.randomUUID();
        Account account = new Account(accountId, "ACCT-BAL-01", UUID.randomUUID(), "USD", new BigDecimal("750.5000"), "ACTIVE", Instant.now());
        when(accountRepository.findById(accountId)).thenReturn(Optional.of(account));

        mockMvc.perform(get("/accounts/{id}/balance", accountId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accountId").value(accountId.toString()))
                .andExpect(jsonPath("$.currency").value("USD"))
                .andExpect(jsonPath("$.availableBalance").value(750.5000));
    }

    @Test
    void debitReturnsReceiptWhenValid() throws Exception {
        UUID accountId = UUID.randomUUID();
        AccountDebitService.DebitReceipt receipt = new AccountDebitService.DebitReceipt(
                accountId, "debit-ref-001", new BigDecimal("50.0000"), "USD"
        );
        when(debitService.debit(eq(accountId), eq("debit-ref-001"), eq(new BigDecimal("50.0000")), eq("USD"))).thenReturn(receipt);

        String json = """
                {
                  "reference": "debit-ref-001",
                  "amount": 50.0000,
                  "currency": "USD"
                }
                """;

        mockMvc.perform(post("/accounts/{id}/debits", accountId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accountId").value(accountId.toString()))
                .andExpect(jsonPath("$.reference").value("debit-ref-001"))
                .andExpect(jsonPath("$.amount").value(50.0000))
                .andExpect(jsonPath("$.currency").value("USD"));
    }

    @Test
    void debitReturnsBadRequestWhenValidationFails() throws Exception {
        UUID accountId = UUID.randomUUID();
        // invalid currency and zero amount
        String json = """
                {
                  "reference": "",
                  "amount": 0.0000,
                  "currency": "invalid"
                }
                """;

        mockMvc.perform(post("/accounts/{id}/debits", accountId)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.detail").value("Validation failed for request content"))
                .andExpect(jsonPath("$.errors").exists());
    }
}
