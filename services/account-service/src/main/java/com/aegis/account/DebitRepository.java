package com.aegis.account;
import org.springframework.data.jpa.repository.JpaRepository; import java.util.Optional; import java.util.UUID;
interface DebitRepository extends JpaRepository<DebitRecord,UUID>{Optional<DebitRecord> findByReference(String reference);}
