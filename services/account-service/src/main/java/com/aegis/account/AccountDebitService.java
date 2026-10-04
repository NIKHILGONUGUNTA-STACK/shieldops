package com.aegis.account;
import org.springframework.http.HttpStatus; import org.springframework.stereotype.Service; import org.springframework.transaction.annotation.Transactional; import org.springframework.web.server.ResponseStatusException;
import java.math.BigDecimal; import java.util.UUID;
@Service class AccountDebitService {
 private final AccountRepository accounts; private final DebitRepository debits;
 AccountDebitService(AccountRepository accounts,DebitRepository debits){this.accounts=accounts;this.debits=debits;}
 @Transactional DebitReceipt debit(UUID id,String reference,BigDecimal amount,String currency){
  var prior=debits.findByReference(reference); if(prior.isPresent()){var d=prior.get();if(!d.accountId.equals(id)||d.amount.compareTo(amount)!=0||!d.currency.equals(currency))throw new ResponseStatusException(HttpStatus.CONFLICT,"Reference already used for a different debit");return new DebitReceipt(id,reference,amount,currency);}
  var account=accounts.findLocked(id).orElseThrow(()->new ResponseStatusException(HttpStatus.NOT_FOUND,"Account not found"));
  if(!"ACTIVE".equals(account.getStatus()))throw new ResponseStatusException(HttpStatus.CONFLICT,"Source account is not active");
  if(!account.getCurrency().equals(currency))throw new ResponseStatusException(HttpStatus.CONFLICT,"Currency mismatch");
  try{account.debit(amount);}catch(IllegalArgumentException e){throw new ResponseStatusException(HttpStatus.CONFLICT,"Insufficient available balance");}
  debits.save(new DebitRecord(reference,id,amount,currency)); return new DebitReceipt(id,reference,amount,currency);
 }
 record DebitReceipt(UUID accountId,String reference,BigDecimal amount,String currency){}
}
