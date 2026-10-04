package com.aegis.account;
import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;
@Entity @Table(name="account_debits",schema="account_data")
class DebitRecord {
 @Id UUID id; @Column(nullable=false,unique=true,length=80) String reference; @Column(nullable=false) UUID accountId; @Column(nullable=false,precision=19,scale=4) BigDecimal amount; @Column(nullable=false,length=3) String currency; @Column(nullable=false) Instant createdAt;
 protected DebitRecord(){} DebitRecord(String ref,UUID account,BigDecimal amount,String currency){id=UUID.randomUUID();reference=ref;accountId=account;this.amount=amount;this.currency=currency;createdAt=Instant.now();}
}
