package com.aegis.account;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;
import jakarta.validation.Valid;
import jakarta.validation.constraints.*;
@RestController
@RequestMapping("/accounts")
public class AccountController {
    private final AccountRepository accounts; private final CustomerClient customers; private final AccountDebitService debitService;
    public AccountController(AccountRepository accounts,CustomerClient customers,AccountDebitService debitService){this.accounts=accounts;this.customers=customers;this.debitService=debitService;}
    @GetMapping public List<AccountView> list(@RequestParam(name="customerId",required=false) UUID customerId){
        var rows=customerId==null?accounts.findAll():accounts.findByCustomerId(customerId);
        return rows.stream().map(a->view(a,false)).toList();
    }
    @GetMapping("/{id}") public AccountView get(@PathVariable("id") UUID id){return view(find(id),true);}
    @GetMapping("/{id}/balance") public Balance balance(@PathVariable("id") UUID id){Account a=find(id);return new Balance(a.getId(),a.getCurrency(),a.getBalance(),a.getStatus());}
    @PostMapping("/{id}/debits") public AccountDebitService.DebitReceipt debit(@PathVariable("id") UUID id,@Valid @RequestBody DebitRequest request){return debitService.debit(id,request.reference(),request.amount(),request.currency());}
    private Account find(UUID id){return accounts.findById(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Account not found"));}
    private AccountView view(Account a,boolean includeCustomer){CustomerClient.CustomerSummary customer=null;if(includeCustomer){try{customer=customers.get(a.getCustomerId());}catch(org.springframework.web.client.RestClientException e){throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,"Customer service unavailable");}}
        return new AccountView(a.getId(),a.getAccountNumber(),a.getCustomerId(),a.getCurrency(),a.getBalance(),a.getStatus(),a.getOpenedAt(),customer);}
    public record Balance(UUID accountId,String currency,BigDecimal availableBalance,String status){}
    public record DebitRequest(@NotBlank @Size(max=80)String reference,@NotNull @DecimalMin("0.0001") @jakarta.validation.constraints.Digits(integer=15,fraction=4)BigDecimal amount,@NotNull @Pattern(regexp="[A-Z]{3}")String currency){}
    public record AccountView(UUID id,String accountNumber,UUID customerId,String currency,BigDecimal balance,String status,java.time.Instant openedAt,CustomerClient.CustomerSummary customer){}
}
