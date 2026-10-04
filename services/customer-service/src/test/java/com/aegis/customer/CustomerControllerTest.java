package com.aegis.customer;
import org.junit.jupiter.api.Test; import java.util.UUID; import static org.junit.jupiter.api.Assertions.*; import static org.mockito.Mockito.*;
class CustomerControllerTest {
 @Test void profileReturnsOnlyCustomerProfileFields(){UUID id=UUID.randomUUID();CustomerService service=mock(CustomerService.class);var profile=new CustomerService.CustomerProfile(id,"CUST-TEST-01","Casey","Example","casey@example.test","US","ACTIVE");when(service.getProfile(id)).thenReturn(profile);var result=new CustomerController(service).profile(id);assertEquals(id,result.id());assertEquals("CUST-TEST-01",result.customerNumber());assertEquals("ACTIVE",result.status());}
}
