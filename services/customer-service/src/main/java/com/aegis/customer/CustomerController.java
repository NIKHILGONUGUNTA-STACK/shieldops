package com.aegis.customer;

import com.aegis.customer.security.TrustTokenUtils;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.util.UUID;

@RestController
@RequestMapping("/customers")
public class CustomerController {
    private final CustomerService customers;

    public CustomerController(CustomerService customers) {
        this.customers = customers;
    }

    @GetMapping("/{id}")
    public CustomerService.CustomerView get(
            @PathVariable("id") UUID id,
            @RequestHeader(value = TrustTokenUtils.CUSTOMER_ID_HEADER, required = false) String callerCustomerId,
            @RequestHeader(value = TrustTokenUtils.ROLES_HEADER, required = false) String callerRoles) {
        checkCustomerAccess(id, callerCustomerId, callerRoles);
        return customers.get(id);
    }

    @GetMapping("/{id}/profile")
    public CustomerService.CustomerProfile profile(
            @PathVariable("id") UUID id,
            @RequestHeader(value = TrustTokenUtils.CUSTOMER_ID_HEADER, required = false) String callerCustomerId,
            @RequestHeader(value = TrustTokenUtils.ROLES_HEADER, required = false) String callerRoles) {
        checkCustomerAccess(id, callerCustomerId, callerRoles);
        return customers.getProfile(id);
    }

    private void checkCustomerAccess(UUID resourceCustomerId, String callerCustomerId, String callerRoles) {
        if (callerRoles != null && (callerRoles.contains("SECURITY_ADMIN") || callerRoles.contains("SECURITY_ANALYST"))) {
            return;
        }
        if (callerCustomerId != null && !callerCustomerId.isBlank()) {
            try {
                UUID callerUuid = UUID.fromString(callerCustomerId.trim());
                if (!callerUuid.equals(resourceCustomerId)) {
                    throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Access to another customer's resources is forbidden");
                }
            } catch (IllegalArgumentException e) {
                throw new ResponseStatusException(HttpStatus.FORBIDDEN, "Invalid customer context");
            }
        }
    }
}
