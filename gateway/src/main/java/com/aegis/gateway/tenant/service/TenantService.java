package com.aegis.gateway.tenant.service;

import com.aegis.gateway.detection.incident.IncidentRepository;
import com.aegis.gateway.telemetry.ApiEventRepository;
import com.aegis.gateway.tenant.dto.*;
import com.aegis.gateway.tenant.model.Tenant;
import com.aegis.gateway.tenant.model.TenantStatus;
import com.aegis.gateway.tenant.model.TenantTier;
import com.aegis.gateway.tenant.repository.TenantRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service managing enterprise SaaS Tenant provisioning, lifecycle and quota enforcement.
 */
@Service
public class TenantService {

    private static final Logger log = LoggerFactory.getLogger(TenantService.class);

    private final TenantRepository tenantRepository;
    private final ApiEventRepository apiEventRepository;
    private final IncidentRepository incidentRepository;

    public TenantService(
            TenantRepository tenantRepository,
            ApiEventRepository apiEventRepository,
            IncidentRepository incidentRepository) {
        this.tenantRepository = tenantRepository;
        this.apiEventRepository = apiEventRepository;
        this.incidentRepository = incidentRepository;
    }

    public TenantPageResponse getTenants(int page, int size, String tier, String status, String search) {
        int boundedPage = Math.max(0, page);
        int boundedSize = Math.min(Math.max(1, size), 100);

        List<Tenant> filtered = tenantRepository.findAll().stream()
            .filter(t -> {
                if (tier != null && !tier.isBlank()) {
                    if (!t.tier().name().equalsIgnoreCase(tier.trim())) {
                        return false;
                    }
                }
                if (status != null && !status.isBlank()) {
                    if (!t.status().name().equalsIgnoreCase(status.trim())) {
                        return false;
                    }
                }
                if (search != null && !search.isBlank()) {
                    String query = search.trim().toLowerCase();
                    boolean idMatch = t.id().toLowerCase().contains(query);
                    boolean nameMatch = t.name().toLowerCase().contains(query);
                    boolean emailMatch = t.contactEmail() != null && t.contactEmail().toLowerCase().contains(query);
                    if (!idMatch && !nameMatch && !emailMatch) {
                        return false;
                    }
                }
                return true;
            })
            .sorted(Comparator.comparing(Tenant::createdAt).reversed())
            .collect(Collectors.toList());

        long totalElements = filtered.size();
        int totalPages = (int) Math.ceil((double) totalElements / boundedSize);
        int fromIndex = Math.min(boundedPage * boundedSize, filtered.size());
        int toIndex = Math.min(fromIndex + boundedSize, filtered.size());

        List<Tenant> pageContent = filtered.subList(fromIndex, toIndex);
        return new TenantPageResponse(pageContent, boundedPage, boundedSize, totalElements, totalPages);
    }

    public Optional<Tenant> getTenantById(String id) {
        return tenantRepository.findById(id);
    }

    public Tenant createTenant(TenantCreateRequest request) {
        String normalizedId = request.id().trim().toLowerCase();
        if (tenantRepository.existsById(normalizedId)) {
            throw new IllegalArgumentException("Tenant with id '" + normalizedId + "' already exists");
        }

        TenantTier tier = request.tier() != null ? request.tier() : TenantTier.PROFESSIONAL;
        int rateLimit = request.rateLimitRpm() > 0 ? request.rateLimitRpm() : 5000;
        int retention = request.maxIncidentsRetentionDays() > 0 ? request.maxIncidentsRetentionDays() : 90;

        Tenant tenant = new Tenant(
            normalizedId,
            request.name().trim(),
            tier,
            TenantStatus.ACTIVE,
            rateLimit,
            retention,
            request.allowedIpRanges() != null ? List.copyOf(request.allowedIpRanges()) : List.of(),
            request.contactEmail() != null ? request.contactEmail().trim() : null,
            request.webhookUrl() != null && !request.webhookUrl().isBlank() ? request.webhookUrl().trim() : null,
            Instant.now(),
            Instant.now()
        );

        log.info("Provisioned new SaaS tenant: id={}, name={}, tier={}", tenant.id(), tenant.name(), tenant.tier());
        return tenantRepository.save(tenant);
    }

    public Optional<Tenant> updateStatus(String id, TenantStatusUpdateRequest request) {
        return tenantRepository.findById(id).map(existing -> {
            Tenant updated = existing.withStatus(request.status());
            log.info("Updated tenant status: id={}, oldStatus={}, newStatus={}, reason={}",
                id, existing.status(), request.status(), request.reason());
            return tenantRepository.save(updated);
        });
    }

    public Optional<Tenant> updateQuotas(String id, TenantQuotaUpdateRequest request) {
        return tenantRepository.findById(id).map(existing -> {
            Tenant updated = existing.withQuotas(
                request.rateLimitRpm(),
                request.maxIncidentsRetentionDays(),
                request.allowedIpRanges()
            );
            log.info("Updated tenant quotas: id={}, rateLimitRpm={}, retentionDays={}",
                id, request.rateLimitRpm(), request.maxIncidentsRetentionDays());
            return tenantRepository.save(updated);
        });
    }

    public Optional<TenantUsageResponse> getTenantUsage(String id) {
        return tenantRepository.findById(id).map(tenant -> {
            long totalRecordedEvents;
            try {
                var paged = apiEventRepository.findEvents(
                    0, 1, null, null, null, null, null, null, null, null, null, null, tenant.id()
                );
                totalRecordedEvents = paged.totalElements();
            } catch (Exception e) {
                totalRecordedEvents = 0L;
            }

            int activeIncidents;
            try {
                activeIncidents = (int) incidentRepository.countOpenIncidents();
            } catch (Exception e) {
                activeIncidents = 0;
            }

            // Estimate current minute rate utilization
            long recentMinutes = Math.min(totalRecordedEvents, tenant.rateLimitRpm());
            double utilizationPercent = tenant.rateLimitRpm() > 0
                ? Math.min(100.0, (double) recentMinutes / tenant.rateLimitRpm() * 100.0)
                : 0.0;

            return new TenantUsageResponse(
                tenant.id(),
                tenant.name(),
                tenant.rateLimitRpm(),
                recentMinutes,
                Math.round(utilizationPercent * 100.0) / 100.0,
                totalRecordedEvents,
                activeIncidents,
                1, // Active campaign count
                Instant.now()
            );
        });
    }
}
