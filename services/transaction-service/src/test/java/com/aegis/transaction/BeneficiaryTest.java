package com.aegis.transaction;
import org.junit.jupiter.api.Test;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
class BeneficiaryTest {
    @Test void newBeneficiaryRequiresVerificationBeforeTransfer() {
        Beneficiary beneficiary = new Beneficiary(UUID.randomUUID(),"Synthetic Payee","EXT-ACCT-90001","USD");
        assertEquals("PENDING",beneficiary.getStatus());
        beneficiary.verify();
        assertEquals("VERIFIED",beneficiary.getStatus());
        assertThrows(IllegalStateException.class,beneficiary::verify);
    }
}
