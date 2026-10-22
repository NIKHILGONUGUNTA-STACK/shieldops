package com.aegis.customer;

import jakarta.persistence.*;
import java.time.Instant;
import java.time.LocalDate;
import java.util.UUID;

@Entity
@Table(name = "customers", schema = "customer_data")
public class Customer {
    @Id private UUID id;
    @Column(nullable = false, unique = true, length = 40) private String customerNumber;
    @Column(nullable = false, length = 80) private String firstName;
    @Column(nullable = false, length = 80) private String lastName;
    @Column(nullable = false, unique = true, length = 160) private String email;
    @Column(nullable = false, length = 2) private String countryCode;
    @Column(nullable = false, length = 20) private String status;
    @Column(nullable = false) private LocalDate createdDate;
    protected Customer() {}
    public Customer(UUID id, String customerNumber, String firstName, String lastName, String email, String countryCode, String status, LocalDate createdDate) {
        this.id = id;
        this.customerNumber = customerNumber;
        this.firstName = firstName;
        this.lastName = lastName;
        this.email = email;
        this.countryCode = countryCode;
        this.status = status;
        this.createdDate = createdDate;
    }
    public UUID getId() { return id; }
    public String getCustomerNumber() { return customerNumber; }
    public String getFirstName() { return firstName; }
    public String getLastName() { return lastName; }
    public String getEmail() { return email; }
    public String getCountryCode() { return countryCode; }
    public String getStatus() { return status; }
    public LocalDate getCreatedDate() { return createdDate; }
}
