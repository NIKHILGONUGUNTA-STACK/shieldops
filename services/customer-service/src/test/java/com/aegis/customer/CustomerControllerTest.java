package com.aegis.customer;

import com.aegis.customer.security.TrustTokenUtils;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpStatus;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.server.ResponseStatusException;

import java.time.LocalDate;
import java.util.UUID;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@WebMvcTest(CustomerController.class)
@Import(ApiExceptionHandler.class)
class CustomerControllerTest {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private CustomerService customerService;

    @Test
    void getCustomerReturnsOkWithJson() throws Exception {
        UUID id = UUID.randomUUID();
        CustomerService.CustomerView view = new CustomerService.CustomerView(
                id, "CUST-TEST-01", "Casey", "Example", "ACTIVE", LocalDate.of(2025, 1, 1)
        );
        when(customerService.get(id)).thenReturn(view);

        mockMvc.perform(get("/customers/{id}", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.customerNumber").value("CUST-TEST-01"))
                .andExpect(jsonPath("$.firstName").value("Casey"))
                .andExpect(jsonPath("$.status").value("ACTIVE"));
    }

    @Test
    void getCustomerReturnsNotFoundProblemDetailWhenMissing() throws Exception {
        UUID id = UUID.randomUUID();
        when(customerService.get(id)).thenThrow(new ResponseStatusException(HttpStatus.NOT_FOUND, "Customer not found"));

        mockMvc.perform(get("/customers/{id}", id))
                .andExpect(status().isNotFound())
                .andExpect(jsonPath("$.status").value(404))
                .andExpect(jsonPath("$.detail").value("Customer not found"));
    }

    @Test
    void getProfileReturnsProfileFields() throws Exception {
        UUID id = UUID.randomUUID();
        CustomerService.CustomerProfile profile = new CustomerService.CustomerProfile(
                id, "CUST-TEST-01", "Casey", "Example", "casey@example.test", "US", "ACTIVE"
        );
        when(customerService.getProfile(id)).thenReturn(profile);

        mockMvc.perform(get("/customers/{id}/profile", id))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(id.toString()))
                .andExpect(jsonPath("$.email").value("casey@example.test"))
                .andExpect(jsonPath("$.countryCode").value("US"));
    }

    @Test
    void getCustomerRejectsCrossCustomerAccessWithForbidden() throws Exception {
        UUID targetId = UUID.randomUUID();
        UUID otherCustomerId = UUID.randomUUID();

        mockMvc.perform(get("/customers/{id}", targetId)
                .header(TrustTokenUtils.CUSTOMER_ID_HEADER, otherCustomerId.toString())
                .header(TrustTokenUtils.ROLES_HEADER, "CUSTOMER"))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.detail").value("Access to another customer's resources is forbidden"));
    }

    @Test
    void getCustomerAllowsSameCustomerAccess() throws Exception {
        UUID targetId = UUID.randomUUID();
        CustomerService.CustomerView view = new CustomerService.CustomerView(
                targetId, "CUST-SELF", "Self", "User", "ACTIVE", LocalDate.of(2025, 1, 1)
        );
        when(customerService.get(targetId)).thenReturn(view);

        mockMvc.perform(get("/customers/{id}", targetId)
                .header(TrustTokenUtils.CUSTOMER_ID_HEADER, targetId.toString())
                .header(TrustTokenUtils.ROLES_HEADER, "CUSTOMER"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(targetId.toString()));
    }

    @Test
    void getCustomerAllowsSecurityAdminAccessToAnyCustomer() throws Exception {
        UUID targetId = UUID.randomUUID();
        CustomerService.CustomerView view = new CustomerService.CustomerView(
                targetId, "CUST-ADMIN-READ", "Admin", "Read", "ACTIVE", LocalDate.of(2025, 1, 1)
        );
        when(customerService.get(targetId)).thenReturn(view);

        mockMvc.perform(get("/customers/{id}", targetId)
                .header(TrustTokenUtils.ROLES_HEADER, "SECURITY_ADMIN"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.id").value(targetId.toString()));
    }
}
