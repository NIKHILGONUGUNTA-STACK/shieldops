package com.aegis.transaction;
import jakarta.persistence.*;
import java.time.Instant;
import java.util.UUID;
@Entity
@Table(name="beneficiaries",schema="transaction_data")
public class Beneficiary {
    @Id private UUID id;
    @Column(nullable=false) private UUID customerId;
    @Column(nullable=false,length=80) private String name;
    @Column(nullable=false,length=34) private String destinationAccountReference;
    @Column(nullable=false,length=3) private String currency;
    @Column(nullable=false,length=12) private String status;
    @Column(nullable=false) private Instant createdAt;
    protected Beneficiary() {}
    Beneficiary(UUID customerId,String name,String destinationAccountReference,String currency){this.id=UUID.randomUUID();this.customerId=customerId;this.name=name;this.destinationAccountReference=destinationAccountReference;this.currency=currency;this.status="PENDING";this.createdAt=Instant.now();}
    public UUID getId(){return id;} public UUID getCustomerId(){return customerId;} public String getName(){return name;} public String getDestinationAccountReference(){return destinationAccountReference;} public String getCurrency(){return currency;} public String getStatus(){return status;} public Instant getCreatedAt(){return createdAt;}
    void verify(){if(!"PENDING".equals(status))throw new IllegalStateException("Only pending beneficiaries can be verified");status="VERIFIED";}
}
