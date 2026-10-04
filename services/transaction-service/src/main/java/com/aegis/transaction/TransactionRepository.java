package com.aegis.transaction;
import org.springframework.data.jpa.repository.JpaRepository;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
public interface TransactionRepository extends JpaRepository<TransactionRecord,UUID>{Optional<TransactionRecord> findByReference(String reference);List<TransactionRecord> findByCustomerId(UUID customerId);}
