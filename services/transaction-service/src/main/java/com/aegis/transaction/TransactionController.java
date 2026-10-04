package com.aegis.transaction;
import jakarta.validation.Valid;
import jakarta.validation.constraints.DecimalMin;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import org.springframework.http.HttpStatus;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;
import java.math.BigDecimal;
import java.util.List;
import java.util.UUID;
@RestController
public class TransactionController {
    private final BeneficiaryRepository beneficiaries; private final TransactionRepository transactions; private final AccountClient accounts;
    public TransactionController(BeneficiaryRepository b,TransactionRepository t,AccountClient a){beneficiaries=b;transactions=t;accounts=a;}
    @GetMapping("/beneficiaries") public List<BeneficiaryView> beneficiaries(@RequestParam(name="customerId",required=false)UUID customerId){return (customerId==null?beneficiaries.findAll():beneficiaries.findByCustomerId(customerId)).stream().map(BeneficiaryView::from).toList();}
    @PostMapping("/beneficiaries") @ResponseStatus(HttpStatus.CREATED) public BeneficiaryView create(@Valid @RequestBody CreateBeneficiary request){return BeneficiaryView.from(beneficiaries.save(new Beneficiary(request.customerId(),request.name(),request.destinationAccountReference(),request.currency())));}
    @GetMapping("/beneficiaries/{id}") public BeneficiaryView beneficiary(@PathVariable("id") UUID id){return BeneficiaryView.from(getBeneficiary(id));}
    @PostMapping("/beneficiaries/{id}/verify") @Transactional public BeneficiaryView verify(@PathVariable("id") UUID id){Beneficiary b=getBeneficiary(id);try{b.verify();}catch(IllegalStateException e){throw new ResponseStatusException(HttpStatus.CONFLICT,e.getMessage());}return BeneficiaryView.from(b);}
    @GetMapping("/transactions") public List<TransactionView> transactions(@RequestParam(name="customerId",required=false)UUID customerId){return (customerId==null?transactions.findAll():transactions.findByCustomerId(customerId)).stream().map(TransactionView::from).toList();}
    @GetMapping("/transactions/{id}") public TransactionView transaction(@PathVariable("id") UUID id){return TransactionView.from(transactions.findById(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Transaction not found")));}
    @PostMapping("/transfers") @ResponseStatus(HttpStatus.CREATED) public TransactionView transfer(@Valid @RequestBody TransferRequest request,@RequestHeader(value="Idempotency-Key",required=false)String key){
        String reference=key==null||key.isBlank()?request.reference():key;
        if(reference==null||reference.isBlank())throw new ResponseStatusException(HttpStatus.BAD_REQUEST,"Idempotency-Key or reference is required");
        var prior=transactions.findByReference(reference);
        TransactionRecord transfer;
        if(prior.isPresent()){
            TransactionRecord existing=prior.get();
            if(!existing.getCustomerId().equals(request.customerId())||!existing.getSourceAccountId().equals(request.sourceAccountId())||!existing.getBeneficiaryId().equals(request.beneficiaryId())||existing.getAmount().compareTo(request.amount())!=0||!existing.getCurrency().equals(request.currency()))throw new ResponseStatusException(HttpStatus.CONFLICT,"Idempotency key was already used for a different transfer");
            if("COMPLETED".equals(existing.getStatus()))return TransactionView.from(existing);
            if(!"PENDING".equals(existing.getStatus()))throw new ResponseStatusException(HttpStatus.CONFLICT,"Transfer is not retryable in its current state");
            transfer=existing;
        } else {
            Beneficiary beneficiary=getBeneficiary(request.beneficiaryId());if(!beneficiary.getCustomerId().equals(request.customerId()))throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Beneficiary does not belong to customer");
            if(!"VERIFIED".equals(beneficiary.getStatus()))throw new ResponseStatusException(HttpStatus.CONFLICT,"Beneficiary must be verified");
            AccountClient.AccountSummary source;
            try{source=accounts.get(request.sourceAccountId());}catch(org.springframework.web.client.RestClientException e){throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,"Account service unavailable");}
            if(!source.customerId().equals(request.customerId()))throw new ResponseStatusException(HttpStatus.FORBIDDEN,"Source account does not belong to customer");
            if(!"ACTIVE".equals(source.status()))throw new ResponseStatusException(HttpStatus.CONFLICT,"Source account is not active");
            if(!source.currency().equals(request.currency())||!beneficiary.getCurrency().equals(request.currency()))throw new ResponseStatusException(HttpStatus.CONFLICT,"Currency mismatch");
            if(source.balance().compareTo(request.amount())<0)throw new ResponseStatusException(HttpStatus.CONFLICT,"Insufficient available balance");
            transfer=transactions.save(new TransactionRecord(reference,request.customerId(),request.sourceAccountId(),request.beneficiaryId(),request.amount(),request.currency()));
            transfer.transition("PENDING");transfer=transactions.save(transfer);
        }
        try{accounts.debit(request.sourceAccountId(),reference,request.amount(),request.currency());transfer.transition("AUTHORIZED");transactions.save(transfer);transfer.transition("COMPLETED");return TransactionView.from(transactions.save(transfer));}
        catch(org.springframework.web.client.HttpClientErrorException e){transfer.transition("FAILED");transactions.save(transfer);throw new ResponseStatusException(HttpStatus.CONFLICT,"Account rejected transfer debit");}
        catch(org.springframework.web.client.RestClientException e){throw new ResponseStatusException(HttpStatus.BAD_GATEWAY,"Account service unavailable; transfer can be retried safely");}
    }
    private Beneficiary getBeneficiary(UUID id){return beneficiaries.findById(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Beneficiary not found"));}
    public record CreateBeneficiary(@NotNull UUID customerId,@NotBlank @jakarta.validation.constraints.Size(max=80)String name,@NotBlank @jakarta.validation.constraints.Size(max=34)String destinationAccountReference,@NotNull @Pattern(regexp="[A-Z]{3}")String currency){}
    public record BeneficiaryView(UUID id,UUID customerId,String name,String destinationAccountReference,String currency,String status,java.time.Instant createdAt){static BeneficiaryView from(Beneficiary b){return new BeneficiaryView(b.getId(),b.getCustomerId(),b.getName(),b.getDestinationAccountReference(),b.getCurrency(),b.getStatus(),b.getCreatedAt());}}
    public record TransactionView(UUID id,String reference,UUID customerId,UUID sourceAccountId,UUID beneficiaryId,BigDecimal amount,String currency,String status,java.time.Instant createdAt,java.time.Instant updatedAt){static TransactionView from(TransactionRecord t){return new TransactionView(t.getId(),t.getReference(),t.getCustomerId(),t.getSourceAccountId(),t.getBeneficiaryId(),t.getAmount(),t.getCurrency(),t.getStatus(),t.getCreatedAt(),t.getUpdatedAt());}}
    public record TransferRequest(@NotNull UUID customerId,@NotNull UUID sourceAccountId,@NotNull UUID beneficiaryId,@NotNull @DecimalMin(value="0.0001")@jakarta.validation.constraints.Digits(integer=15,fraction=4)BigDecimal amount,@NotNull @Pattern(regexp="[A-Z]{3}")String currency,@jakarta.validation.constraints.Size(max=80)String reference){}
}
