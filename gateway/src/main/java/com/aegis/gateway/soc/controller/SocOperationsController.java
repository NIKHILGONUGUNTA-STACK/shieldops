package com.aegis.gateway.soc.controller;

import com.aegis.gateway.soc.model.*;
import com.aegis.gateway.soc.service.SocOperationsService;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class SocOperationsController {

    private final SocOperationsService socOperationsService;

    public SocOperationsController(SocOperationsService socOperationsService) {
        this.socOperationsService = socOperationsService;
    }

    @GetMapping(value = {"/api/v1/soc/network-intelligence", "/soc/network-intelligence"}, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<NetworkIntelligenceResponse> getNetworkIntelligence(
            @RequestParam(name = "windowHours", defaultValue = "24") int windowHours,
            @RequestParam(name = "limit", defaultValue = "50") int limit) {
        NetworkIntelligenceResponse response = socOperationsService.getNetworkIntelligence(windowHours, limit);
        return ResponseEntity.ok(response);
    }

    @GetMapping(value = {"/api/v1/soc/identity-intelligence", "/soc/identity-intelligence"}, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<IdentityIntelligenceResponse> getIdentityIntelligence(
            @RequestParam(name = "windowHours", defaultValue = "24") int windowHours,
            @RequestParam(name = "limit", defaultValue = "50") int limit) {
        IdentityIntelligenceResponse response = socOperationsService.getIdentityIntelligence(windowHours, limit);
        return ResponseEntity.ok(response);
    }

    @GetMapping(value = {"/api/v1/soc/tenant-activity", "/soc/tenant-activity"}, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<TenantActivityResponse> getTenantActivity(
            @RequestParam(name = "windowHours", defaultValue = "24") int windowHours,
            @RequestParam(name = "limit", defaultValue = "50") int limit) {
        TenantActivityResponse response = socOperationsService.getTenantActivity(windowHours, limit);
        return ResponseEntity.ok(response);
    }

    @GetMapping(value = {"/api/v1/soc/infrastructure-observability", "/soc/infrastructure-observability"}, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<InfrastructureObservabilityResponse> getInfrastructureObservability() {
        InfrastructureObservabilityResponse response = socOperationsService.getInfrastructureObservability();
        return ResponseEntity.ok(response);
    }
}
