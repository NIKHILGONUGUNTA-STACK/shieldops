package com.aegis.customer;

import org.junit.jupiter.api.Test;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class CustomerServiceTest {
    private final CustomerRepository repository = mock(CustomerRepository.class);
    private final CustomerService service = new CustomerService(repository);

    @Test
    void getReturnsCustomerViewWhenFound() {
        UUID id = UUID.randomUUID();
        Customer customer = new Customer(
                id, "CUST-001", "Jane", "Doe",
                "jane@example.test", "US", "ACTIVE", LocalDate.of(2025, 1, 1)
        );
        when(repository.findById(id)).thenReturn(Optional.of(customer));

        CustomerService.CustomerView view = service.get(id);
        assertEquals(id, view.id());
        assertEquals("CUST-001", view.customerNumber());
        assertEquals("Jane", view.firstName());
        assertEquals("ACTIVE", view.status());
    }

    @Test
    void getThrowsNotFoundWhenCustomerDoesNotExist() {
        UUID id = UUID.randomUUID();
        when(repository.findById(id)).thenReturn(Optional.empty());

        ResponseStatusException ex = assertThrows(ResponseStatusException.class, () -> service.get(id));
        assertEquals(404, ex.getStatusCode().value());
    }

    @Test
    void getProfileReturnsCustomerProfileWhenFound() {
        UUID id = UUID.randomUUID();
        Customer customer = new Customer(
                id, "CUST-002", "John", "Smith",
                "john@example.test", "GB", "ACTIVE", LocalDate.of(2025, 2, 1)
        );
        when(repository.findById(id)).thenReturn(Optional.of(customer));

        CustomerService.CustomerProfile profile = service.getProfile(id);
        assertEquals(id, profile.id());
        assertEquals("CUST-002", profile.customerNumber());
        assertEquals("john@example.test", profile.email());
        assertEquals("GB", profile.countryCode());
    }
}
