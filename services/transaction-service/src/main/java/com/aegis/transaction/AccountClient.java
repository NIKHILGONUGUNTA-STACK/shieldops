package com.aegis.transaction;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;
import java.math.BigDecimal;
import java.util.UUID;
@Component
public class AccountClient {
    private final RestClient client;
    public AccountClient(RestClient.Builder builder,@Value("${services.account.base-url:http://localhost:8082}")String url){client=builder.baseUrl(url).build();}
    public AccountSummary get(UUID id){return client.get().uri("/accounts/{id}",id).retrieve().body(AccountSummary.class);}
    public void debit(UUID id,String reference,BigDecimal amount,String currency){client.post().uri("/accounts/{id}/debits",id).body(new DebitRequest(reference,amount,currency)).retrieve().toBodilessEntity();}
    private record DebitRequest(String reference,BigDecimal amount,String currency){}
    public record AccountSummary(UUID id,String accountNumber,UUID customerId,String currency,BigDecimal balance,String status,java.time.Instant openedAt,Object customer){}
}
