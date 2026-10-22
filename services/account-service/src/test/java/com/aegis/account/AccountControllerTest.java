package com.aegis.account;

import com.aegis.account.security.TrustTokenUtils;
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

        mockMvc.perform(get("/accounts").param("customerId", customerId.toString()))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(accountId.toString()))
                .andExpect(jsonPath("$[0].customerId").value(customerId.toString()));
    }

    @Test
    void getAccountReturnsAccountWithCustomer() throws Exception {
        UUID accountId = UUID.randomUUID();
        UUID customerId = UUID.randomUUID();
        Account account = new Account(accountId, "ACCT-03", customerId, "USD", new BigDecimal("300.0000"), "ACTIVE", Instant.now());
        CustomerClient.CustomerSummary customer = new CustomerClient.CustomerSummary(
                customerId, "CUST-03", "Morgan", "Lee", "morgan@example.test", "US", "ACTIVE"
        );
        when(accountRepository.findById(accountId)).thenReturn(Optional.of(account));
        when(customerClient.get(customerId)).thenReturn(customer);

        mockMvc.perform(get("/accounts/{id}", accountId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(accountId.toString()))
                .andExpect(jsonPath("$.customer.customerNumber").value("CUST-03"));
    }

    @Test
    void getAccountReturnsNotFoundWhenMissing() throws Exception {
        UUID accountId = UUID.randomUUID();
        when(accountRepository.findById(accountId)).thenReturn(Optional.empty());

        mockMvc.perform(get("/accounts/{id}", accountId))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.detail").value("Account not found"));
    }

    @Test
    void balanceReturnsBalanceView() throws Exception {
        UUID accountId = UUID.randomUUID();
        UUID customerId = UUID.randomUUID();
        Account account = new Account(accountId, "ACCT-04", customerId, "USD", new BigDecimal("450.5000"), "ACTIVE", Instant.now());
        when(accountRepository.findById(accountId)).thenReturn(Optional.of(account));

        mockMvc.perform(get("/accounts/{id}/balance", accountId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.accountId").value(accountId.toString()))
                .andExpect(jsonPath("$.availableBalance").value(450.5000))
                .andExpect(jsonPath("$.currency").value("USD"));
    }

    @Test
    void debitReturnsReceiptWhenSuccessful() throws Exception {
        UUID accountId = UUID.randomUUID();
        UUID customerId = UUID.randomUUID();
        Account account = new Account(accountId, "ACCT-05", customerId, "USD", new BigDecimal("500.0000"), "ACTIVE", Instant.now());
        AccountDebitService.DebitReceipt receipt = new AccountDebitService.DebitReceipt(
                accountId, "debit-ref-001", new BigDecimal("50.0000"), "USD"
        );
        when(accountRepository.findById(accountId)).thenReturn(Optional.of(account));
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

    @Test
    void balanceRejectsCrossCustomerAccess() throws Exception {
        UUID accountId = UUID.randomUUID();
        UUID ownerId = UUID.randomUUID();
        UUID attackerCustomerId = UUID.randomUUID();
        Account account = new Account(accountId, "ACCT-SEC-01", ownerId, "USD", new BigDecimal("999.0000"), "ACTIVE", Instant.now());
        when(accountRepository.findById(accountId)).thenReturn(Optional.of(account));

        mockMvc.perform(get("/accounts/{id}/balance", accountId)
                .header(TrustTokenUtils.CUSTOMER_ID_HEADER, attackerCustomerId.toString())
                .header(TrustTokenUtils.ROLES_HEADER, "CUSTOMER"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.detail").value("Access to another customer's account is forbidden"));
    }

    @Test
    void listRejectsCrossCustomerQueryParam() throws Exception {
        UUID callerCustomerId = UUID.randomUUID();
        UUID victimCustomerId = UUID.randomUUID();

        mockMvc.perform(get("/accounts")
                .param("customerId", victimCustomerId.toString())
                .header(TrustTokenUtils.CUSTOMER_ID_HEADER, callerCustomerId.toString())
                .header(TrustTokenUtils.ROLES_HEADER, "CUSTOMER"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.detail").value("Access to another customer's accounts is forbidden"));
    }

    @Test
    void balanceAllowsSecurityAdminAccess() throws Exception {
        UUID accountId = UUID.randomUUID();
        UUID ownerId = UUID.randomUUID();
        Account account = new Account(accountId, "ACCT-SEC-02", ownerId, "USD", new BigDecimal("500.0000"), "ACTIVE", Instant.now());
        when(accountRepository.findById(accountId)).thenReturn(Optional.of(account));

        mockMvc.perform(get("/accounts/{id}/balance", accountId)
                .header(TrustTokenUtils.ROLES_HEADER, "SECURITY_ADMIN"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.availableBalance").value(500.0000));
    }
}
