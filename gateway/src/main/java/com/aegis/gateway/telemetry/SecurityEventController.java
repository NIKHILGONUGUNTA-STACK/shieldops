package com.aegis.gateway.telemetry;

import com.aegis.gateway.security.ResourceNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.UUID;

@RestController
public class SecurityEventController {
    private static final Logger log = LoggerFactory.getLogger(SecurityEventController.class);
    private final ApiEventRepository apiEventRepository;

    public SecurityEventController(ApiEventRepository apiEventRepository) {
        this.apiEventRepository = apiEventRepository;
    }

    @GetMapping(value = {"/api/v1/security/events", "/security/events"}, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<?> getSecurityEvents(
            @RequestParam(name = "page", defaultValue = "0") int page,
            @RequestParam(name = "size", defaultValue = "20") int size,
            @RequestParam(name = "statusCode", required = false) Integer statusCode,
            @RequestParam(name = "httpMethod", required = false) String httpMethod,
            @RequestParam(name = "customerId", required = false) String customerId,
            @RequestParam(name = "sourceIp", required = false) String sourceIp,
            @RequestParam(name = "anomalyFlags", required = false) String anomalyFlags,
            @RequestParam(name = "resourceType", required = false) String resourceType,
            @RequestParam(name = "from", required = false) String fromStr,
            @RequestParam(name = "to", required = false) String toStr,
            @RequestParam(name = "correlationId", required = false) String correlationId) {
        try {
            Instant from = null;
            if (fromStr != null && !fromStr.isBlank()) {
                try {
                    from = Instant.parse(fromStr.trim());
                } catch (DateTimeParseException ex) {
                    throw new IllegalArgumentException("Invalid 'from' timestamp: must be valid ISO-8601 UTC format (e.g. 2026-10-26T17:00:00Z)");
                }
            }

            Instant to = null;
            if (toStr != null && !toStr.isBlank()) {
                try {
                    to = Instant.parse(toStr.trim());
                } catch (DateTimeParseException ex) {
                    throw new IllegalArgumentException("Invalid 'to' timestamp: must be valid ISO-8601 UTC format (e.g. 2026-10-26T17:00:00Z)");
                }
            }

            if (from != null && to != null && from.isAfter(to)) {
                throw new IllegalArgumentException("Invalid time range: 'from' timestamp must not be after 'to' timestamp");
            }

            SecurityEventPageResponse response;
            if (customerId == null && sourceIp == null && anomalyFlags == null && resourceType == null && from == null && to == null && correlationId == null) {
                response = apiEventRepository.findEvents(page, size, statusCode, httpMethod);
            } else {
                response = apiEventRepository.findEvents(
                    page, size, statusCode, httpMethod, customerId, sourceIp, anomalyFlags, resourceType, from, to, correlationId
                );
            }
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException iae) {
            throw iae;
        } catch (DataAccessException dae) {
            log.error("Telemetry database error reading security events: {}", dae.getMessage(), dae);
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.SERVICE_UNAVAILABLE,
                "Telemetry event store is currently unavailable"
            );
            problem.setTitle("Service Unavailable");
            problem.setType(URI.create("https://aegis.dev/errors/telemetry-unavailable"));
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem);
        }
    }

    @GetMapping(value = {"/api/v1/security/events/{id}", "/security/events/{id}"}, produces = MediaType.APPLICATION_JSON_VALUE)
    @PreAuthorize("hasAnyRole('SECURITY_ANALYST', 'SECURITY_ADMIN')")
    public ResponseEntity<SecurityEventResponse> getSecurityEventById(@PathVariable("id") String idStr) {
        UUID eventId;
        try {
            eventId = UUID.fromString(idStr.trim());
        } catch (IllegalArgumentException ex) {
            throw new ResourceNotFoundException("Security event not found with ID: " + idStr);
        }

        SecurityEventResponse event = apiEventRepository.findById(eventId)
            .orElseThrow(() -> new ResourceNotFoundException("Security event not found with ID: " + eventId));

        return ResponseEntity.ok(event);
    }
}
