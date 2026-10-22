package com.aegis.transaction;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(TransactionController.class)
@Import(ApiExceptionHandler.class)
class TransactionControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private TransactionService transactionService;

    @Test
    void listBeneficiariesReturnsJsonArray() throws Exception {
        UUID customerId = UUID.randomUUID();
        UUID benId = UUID.randomUUID();
        TransactionController.BeneficiaryView view = new TransactionController.BeneficiaryView(
                benId, customerId, "Payee One", "DEST-01", "USD", "VERIFIED", Instant.now()
        );
        when(transactionService.listBeneficiaries(customerId)).thenReturn(List.of(view));

        mockMvc.perform(get("/beneficiaries?customerId={customerId}", customerId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$[0].id").value(benId.toString()))
                .andExpect(jsonPath("$[0].name").value("Payee One"))
                .andExpect(jsonPath("$[0].status").value("VERIFIED"));
    }

    @Test
    void createBeneficiaryReturnsCreatedWhenValid() throws Exception {
        UUID customerId = UUID.randomUUID();
        UUID benId = UUID.randomUUID();
        TransactionController.BeneficiaryView view = new TransactionController.BeneficiaryView(
                benId, customerId, "New Payee", "DEST-02", "USD", "PENDING", Instant.now()
        );
        when(transactionService.createBeneficiary(any())).thenReturn(view);

        String json = """
                {
                  "customerId": "%s",
                  "name": "New Payee",
                  "destinationAccountReference": "DEST-02",
                  "currency": "USD"
                }
                """.formatted(customerId);

        mockMvc.perform(post("/beneficiaries")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(benId.toString()))
                .andExpect(jsonPath("$.status").value("PENDING"));
    }

    @Test
    void createBeneficiaryReturnsBadRequestWhenInvalid() throws Exception {
        // missing name and invalid currency
        String json = """
                {
                  "customerId": "%s",
                  "name": "",
                  "destinationAccountReference": "DEST-02",
                  "currency": "TOOLONG"
                }
                """.formatted(UUID.randomUUID());

        mockMvc.perform(post("/beneficiaries")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.errors").exists());
    }

    @Test
    void verifyBeneficiaryReturnsOk() throws Exception {
        UUID benId = UUID.randomUUID();
        TransactionController.BeneficiaryView view = new TransactionController.BeneficiaryView(
                benId, UUID.randomUUID(), "Payee", "DEST-01", "USD", "VERIFIED", Instant.now()
        );
        when(transactionService.verifyBeneficiary(benId)).thenReturn(view);

        mockMvc.perform(post("/beneficiaries/{id}/verify", benId))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.status").value("VERIFIED"));
    }

    @Test
    void transferReturnsCreatedWhenValid() throws Exception {
        UUID customerId = UUID.randomUUID();
        UUID sourceAccountId = UUID.randomUUID();
        UUID beneficiaryId = UUID.randomUUID();
        UUID txId = UUID.randomUUID();
        String ref = "transfer-mockmvc-01";

        TransactionController.TransactionView view = new TransactionController.TransactionView(
                txId, ref, customerId, sourceAccountId, beneficiaryId,
                new BigDecimal("45.0000"), "USD", "COMPLETED", Instant.now(), Instant.now()
        );
        when(transactionService.transfer(any(), eq(ref))).thenReturn(view);

        String json = """
                {
                  "customerId": "%s",
                  "sourceAccountId": "%s",
                  "beneficiaryId": "%s",
                  "amount": 45.0000,
                  "currency": "USD",
                  "reference": "%s"
                }
                """.formatted(customerId, sourceAccountId, beneficiaryId, ref);

        mockMvc.perform(post("/transfers")
                        .header("Idempotency-Key", ref)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.id").value(txId.toString()))
                .andExpect(jsonPath("$.reference").value(ref))
                .andExpect(jsonPath("$.status").value("COMPLETED"));
    }

    @Test
    void transferReturnsBadRequestWhenValidationFails() throws Exception {
        String json = """
                {
                  "customerId": null,
                  "sourceAccountId": null,
                  "beneficiaryId": null,
                  "amount": -5.0000,
                  "currency": "INVALID"
                }
                """;

        mockMvc.perform(post("/transfers")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.status").value(400))
                .andExpect(jsonPath("$.errors").exists());
    }
}
