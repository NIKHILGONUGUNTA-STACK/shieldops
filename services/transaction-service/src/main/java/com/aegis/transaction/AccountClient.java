package com.aegis.transaction;

import com.aegis.transaction.security.TrustTokenUtils;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.math.BigDecimal;
import java.util.UUID;

@Component
public class AccountClient {
    private final RestClient client;

    public AccountClient(
            RestClient.Builder builder,
            @Value("${services.account.base-url:http://localhost:8082}") String url,
            @Value("${aegis.security.internal-secret:aegis-internal-trust-secret-key-32chars!}") String internalSecret) {
        this.client = builder.baseUrl(url)
            .requestInterceptor((request, body, execution) -> {
                String correlationId = MDC.get("correlationId");
                if (correlationId == null || correlationId.isBlank()) {
                    correlationId = UUID.randomUUID().toString();
                }
                String userId = MDC.get("userId");
                String attestation = TrustTokenUtils.buildAttestationHeader(correlationId, userId, internalSecret);

                request.getHeaders().set(TrustTokenUtils.CORRELATION_ID_HEADER, correlationId);
                request.getHeaders().set(TrustTokenUtils.SIGNATURE_HEADER, attestation);
                if (userId != null && !userId.isBlank()) {
                    request.getHeaders().set(TrustTokenUtils.USER_ID_HEADER, userId);
                }
                return execution.execute(request, body);
            })
            .build();
    }

    public AccountSummary get(UUID id) {
        return client.get().uri("/accounts/{id}", id).retrieve().body(AccountSummary.class);
    }

    public void debit(UUID id, String reference, BigDecimal amount, String currency) {
        client.post()
            .uri("/accounts/{id}/debits", id)
            .body(new DebitRequest(reference, amount, currency))
            .retrieve()
            .toBodilessEntity();
    }

    private record DebitRequest(String reference, BigDecimal amount, String currency) {}
    public record AccountSummary(UUID id, String accountNumber, UUID customerId, String currency, BigDecimal balance, String status, java.time.Instant openedAt, Object customer) {}
}
