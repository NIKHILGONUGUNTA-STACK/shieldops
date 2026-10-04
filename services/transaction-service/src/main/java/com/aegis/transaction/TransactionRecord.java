package com.aegis.transaction;
import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;
@Entity
@Table(name="transactions",schema="transaction_data")
public class TransactionRecord {
    @Id private UUID id;
    @Column(nullable=false,unique=true,length=80) private String reference;
    @Column(nullable=false) private UUID customerId;
    @Column(nullable=false) private UUID sourceAccountId;
    @Column(nullable=false) private UUID beneficiaryId;
    @Column(nullable=false,precision=19,scale=4) private BigDecimal amount;
    @Column(nullable=false,length=3) private String currency;
    @Column(nullable=false,length=12) private String status;
    @Column(nullable=false) private Instant createdAt;
    @Column(nullable=false) private Instant updatedAt;
    protected TransactionRecord() {}
    TransactionRecord(String reference,UUID customerId,UUID sourceAccountId,UUID beneficiaryId,BigDecimal amount,String currency){this.id=UUID.randomUUID();this.reference=reference;this.customerId=customerId;this.sourceAccountId=sourceAccountId;this.beneficiaryId=beneficiaryId;this.amount=amount;this.currency=currency;this.status="CREATED";this.createdAt=Instant.now();this.updatedAt=this.createdAt;}
    void transition(String next){if(!java.util.Map.of("CREATED",java.util.Set.of("PENDING","FAILED"),"PENDING",java.util.Set.of("AUTHORIZED","FAILED"),"AUTHORIZED",java.util.Set.of("COMPLETED","FAILED")).getOrDefault(status,java.util.Set.of()).contains(next))throw new IllegalStateException("Invalid transaction status transition");status=next;updatedAt=Instant.now();}
    public UUID getId(){return id;} public String getReference(){return reference;} public UUID getCustomerId(){return customerId;} public UUID getSourceAccountId(){return sourceAccountId;} public UUID getBeneficiaryId(){return beneficiaryId;} public BigDecimal getAmount(){return amount;} public String getCurrency(){return currency;} public String getStatus(){return status;} public Instant getCreatedAt(){return createdAt;} public Instant getUpdatedAt(){return updatedAt;}
}
