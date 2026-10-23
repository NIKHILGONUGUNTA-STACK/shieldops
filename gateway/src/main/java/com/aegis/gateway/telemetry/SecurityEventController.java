package com.aegis.gateway.telemetry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

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
            @RequestParam(name = "httpMethod", required = false) String httpMethod) {
        try {
            SecurityEventPageResponse response = apiEventRepository.findEvents(page, size, statusCode, httpMethod);
            return ResponseEntity.ok(response);
        } catch (DataAccessException dae) {
            log.error("Telemetry database error reading security events: {}", dae.getMessage(), dae);
            ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                HttpStatus.SERVICE_UNAVAILABLE,
                "Telemetry event store is currently unavailable"
            );
            problem.setTitle("Service Unavailable");
            problem.setType(URI.create("https://aegis.local/errors/telemetry-unavailable"));
            return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE).body(problem);
        }
    }
}
