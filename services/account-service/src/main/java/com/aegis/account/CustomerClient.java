package com.aegis.account;

import com.aegis.account.security.TrustTokenUtils;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.UUID;

@Component
public class CustomerClient {
    private final RestClient client;

    public CustomerClient(
            RestClient.Builder builder,
            @Value("${services.customer.base-url:http://localhost:8081}") String baseUrl,
            @Value("${aegis.security.internal-secret:aegis-internal-trust-secret-key-32chars!}") String internalSecret) {
        this.client = builder.baseUrl(baseUrl)
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

    public CustomerSummary get(UUID id) {
        return client.get().uri("/customers/{id}/profile", id).retrieve().body(CustomerSummary.class);
    }

    public record CustomerSummary(UUID id, String customerNumber, String firstName, String lastName, String email, String countryCode, String status) {}
}
