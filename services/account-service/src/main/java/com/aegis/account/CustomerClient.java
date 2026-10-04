package com.aegis.account;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import java.util.UUID;
@Component
public class CustomerClient {
    private final RestClient client;
    public CustomerClient(RestClient.Builder builder, @Value("${services.customer.base-url:http://localhost:8081}") String baseUrl) { client=builder.baseUrl(baseUrl).build(); }
    public CustomerSummary get(UUID id) { return client.get().uri("/customers/{id}/profile",id).retrieve().body(CustomerSummary.class); }
    public record CustomerSummary(UUID id, String customerNumber, String firstName, String lastName, String email, String countryCode, String status) {}
}
