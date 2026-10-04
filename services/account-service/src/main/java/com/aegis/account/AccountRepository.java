package com.aegis.account;
import java.util.List;
import java.util.UUID;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import jakarta.persistence.LockModeType;
public interface AccountRepository extends JpaRepository<Account,UUID> { List<Account> findByCustomerId(UUID customerId); @Lock(LockModeType.PESSIMISTIC_WRITE) @Query("select a from Account a where a.id=:id") java.util.Optional<Account> findLocked(@Param("id") UUID id); }
