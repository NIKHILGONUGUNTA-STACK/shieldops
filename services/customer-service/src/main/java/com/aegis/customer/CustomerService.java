package com.aegis.customer;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;
import java.util.UUID;

@Service
public class CustomerService {
    private final CustomerRepository customers;
    public CustomerService(CustomerRepository customers) { this.customers = customers; }

    public CustomerView get(UUID id) {
        Customer c = customers.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,"Customer not found"));
        return new CustomerView(c.getId(),c.getCustomerNumber(),c.getFirstName(),c.getLastName(),c.getStatus(),c.getCreatedDate());
    }

    public CustomerProfile getProfile(UUID id) {
        Customer c = customers.findById(id).orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,"Customer not found"));
        return new CustomerProfile(c.getId(),c.getCustomerNumber(),c.getFirstName(),c.getLastName(),c.getEmail(),c.getCountryCode(),c.getStatus());
    }

    public record CustomerView(UUID id,String customerNumber,String firstName,String lastName,String status,java.time.LocalDate createdDate) {}
    public record CustomerProfile(UUID id,String customerNumber,String firstName,String lastName,String email,String countryCode,String status) {}
}
