package com.aegis.transaction;
import org.junit.jupiter.api.Test;
import java.math.BigDecimal;
import java.util.UUID;
import static org.junit.jupiter.api.Assertions.*;
class TransactionRecordTest {
    @Test void storesFinancialAmountExactlyAndEnforcesStatusTransitions() {
        BigDecimal amount = new BigDecimal("123.4500");
        TransactionRecord record = new TransactionRecord("synthetic-ref-1",UUID.randomUUID(),UUID.randomUUID(),UUID.randomUUID(),amount,"USD");
        assertEquals("CREATED",record.getStatus());
        assertEquals(0,amount.compareTo(record.getAmount()));
        assertEquals(4,record.getAmount().scale());
        assertNotNull(record.getCreatedAt());
        assertEquals(record.getCreatedAt(),record.getUpdatedAt());
        record.transition("PENDING"); record.transition("AUTHORIZED"); record.transition("COMPLETED");
        assertEquals("COMPLETED",record.getStatus());
        assertThrows(IllegalStateException.class,()->record.transition("PENDING"));
    }
}
