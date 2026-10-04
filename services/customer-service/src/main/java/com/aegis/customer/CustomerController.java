package com.aegis.customer;

import org.springframework.web.bind.annotation.*;
import java.util.UUID;

@RestController
@RequestMapping("/customers")
public class CustomerController {
    private final CustomerService customers;
    public CustomerController(CustomerService customers) { this.customers = customers; }
    @GetMapping("/{id}") public CustomerService.CustomerView get(@PathVariable("id") UUID id) { return customers.get(id); }
    @GetMapping("/{id}/profile") public CustomerService.CustomerProfile profile(@PathVariable("id") UUID id) { return customers.getProfile(id); }
}
