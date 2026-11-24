package com.aegis.gateway.tenant.repository;

import com.aegis.gateway.tenant.model.Tenant;
import com.aegis.gateway.tenant.model.TenantStatus;
import com.aegis.gateway.tenant.model.TenantTier;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Enterprise thread-safe registry repository for SaaS tenants.
 */
@Repository
public class TenantRepository {

    private final Map<String, Tenant> tenants = new ConcurrentHashMap<>();

    public TenantRepository() {
        seedDefaultTenants();
    }

    private void seedDefaultTenants() {
        Instant now = Instant.now();

        save(new Tenant(
            "tenant-fintech-us",
            "Fintech US Production",
            TenantTier.ENTERPRISE,
            TenantStatus.ACTIVE,
            10000,
            365,
            List.of("10.0.0.0/8", "192.168.0.0/16"),
            "admin@fintech-us.shieldops.internal",
            "https://hooks.slack.com/services/T00/B00/fintech-us",
            now.minusSeconds(86400 * 30),
            now
        ));

        save(new Tenant(
            "tenant-banking-eu",
            "Apex Global Bank EU",
            TenantTier.ENTERPRISE,
            TenantStatus.ACTIVE,
            15000,
            365,
            List.of("172.16.0.0/12"),
            "security@apex-bank.internal",
            "https://events.pagerduty.com/v2/enqueue",
            now.minusSeconds(86400 * 20),
            now
        ));

        save(new Tenant(
            "tenant-retail-asia",
            "Retail Gateway APAC",
            TenantTier.PROFESSIONAL,
            TenantStatus.ACTIVE,
            5000,
            90,
            List.of(),
            "ops@retail-apac.internal",
            null,
            now.minusSeconds(86400 * 10),
            now
        ));

        save(new Tenant(
            "tenant-global-sandbox",
            "Global Security Sandbox",
            TenantTier.STARTER,
            TenantStatus.ACTIVE,
            1000,
            30,
            List.of(),
            "sandbox@shieldops.internal",
            null,
            now.minusSeconds(86400 * 5),
            now
        ));
    }

    public List<Tenant> findAll() {
        return new ArrayList<>(tenants.values());
    }

    public Optional<Tenant> findById(String id) {
        if (id == null) return Optional.empty();
        return Optional.ofNullable(tenants.get(id.trim().toLowerCase()));
    }

    public Tenant save(Tenant tenant) {
        if (tenant == null || tenant.id() == null) {
            throw new IllegalArgumentException("Tenant and tenant id must not be null");
        }
        tenants.put(tenant.id().trim().toLowerCase(), tenant);
        return tenant;
    }

    public boolean existsById(String id) {
        if (id == null) return false;
        return tenants.containsKey(id.trim().toLowerCase());
    }

    public boolean deleteById(String id) {
        if (id == null) return false;
        return tenants.remove(id.trim().toLowerCase()) != null;
    }

    public long count() {
        return tenants.size();
    }
}
