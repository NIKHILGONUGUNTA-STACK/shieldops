package com.aegis.customer;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.test.context.ActiveProfiles;

import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@DataJpaTest
@ActiveProfiles("test")
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
class CustomerRepositoryTest {

    @Autowired
    private CustomerRepository customerRepository;

    @Test
    void persistsAndRetrievesCustomerSuccessfully() {
        UUID id = UUID.randomUUID();
        Customer customer = new Customer(
                id, "CUST-99999", "Test", "User",
                "test.user@example.test", "US", "ACTIVE", LocalDate.now()
        );
        customerRepository.save(customer);

        Optional<Customer> found = customerRepository.findById(id);
        assertTrue(found.isPresent());
        assertEquals("CUST-99999", found.get().getCustomerNumber());
        assertEquals("Test", found.get().getFirstName());
        assertEquals("ACTIVE", found.get().getStatus());
    }
}
