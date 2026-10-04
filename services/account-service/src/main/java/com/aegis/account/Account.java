package com.aegis.account;
import jakarta.persistence.*;
import java.math.BigDecimal;
import java.time.Instant;
import java.util.UUID;
@Entity
@Table(name="accounts", schema="account_data")
public class Account {
    @Id private UUID id;
    @Column(nullable=false, unique=true, length=34) private String accountNumber;
    @Column(nullable=false) private UUID customerId;
    @Column(nullable=false, length=3) private String currency;
    @Column(nullable=false, precision=19, scale=4) private BigDecimal balance;
    @Column(nullable=false, length=12) private String status;
    @Column(nullable=false) private Instant openedAt;
    protected Account() {}
    public UUID getId(){return id;} public String getAccountNumber(){return accountNumber;} public UUID getCustomerId(){return customerId;}
    public String getCurrency(){return currency;} public BigDecimal getBalance(){return balance;} public String getStatus(){return status;} public Instant getOpenedAt(){return openedAt;}
    void debit(BigDecimal amount){if(!"ACTIVE".equals(status))throw new IllegalStateException("Account is not active");if(balance.compareTo(amount)<0)throw new IllegalArgumentException("Insufficient available balance");balance=balance.subtract(amount);}
}
