package com.aegis.gateway.workflow;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Pattern;

/**
 * Manages active session workflow progression and evaluates deterministic workflow invariants.
 */
@Service
public class WorkflowStateService {
    private static final Logger log = LoggerFactory.getLogger(WorkflowStateService.class);

    private static final Duration SESSION_TTL = Duration.ofMinutes(10);
    private static final String REDIS_PREFIX = "aegis:workflow:session:";
    private static final Pattern PATH_ID_REGEX = Pattern.compile(
        "/([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}|\\d+|cust-[a-zA-Z0-9]+|acc-[a-zA-Z0-9]+|txn-[a-zA-Z0-9]+)(?=/|$)"
    );

    private final StringRedisTemplate redisTemplate;
    // High-performance in-memory fallback for local execution or test isolation
    private final Map<String, Set<String>> memoryStore = new ConcurrentHashMap<>();
    private final List<WorkflowRule> rules = new ArrayList<>();

    @Autowired
    public WorkflowStateService(@Autowired(required = false) StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
        initDefaultRules();
    }

    private void initDefaultRules() {
        rules.add(new WorkflowRule(
            "RULE-WF-TRANSFER-01",
            "POST",
            "^/(api/v1/)?(transactions|transfers)(/.*)?$",
            List.of(
                "GET /api/v1/accounts",
                "GET /api/v1/customers/{id}",
                "GET /api/v1/accounts/{id}/balance",
                "GET /accounts",
                "GET /customers"
            ),
            "Payment and funds transfer execution requires prior account lookup, balance inquiry, or profile review."
        ));

        rules.add(new WorkflowRule(
            "RULE-WF-ACCOUNT-DELETE-01",
            "DELETE",
            "^/(api/v1/)?accounts/[a-zA-Z0-9_-]+$",
            List.of(
                "GET /api/v1/accounts/{id}",
                "GET /api/v1/accounts",
                "GET /accounts"
            ),
            "Account deletion requires prior account details retrieval."
        ));
    }

    public static String normalizePath(String rawPath) {
        if (rawPath == null || rawPath.isBlank()) {
            return "/";
        }
        String clean = rawPath.split("\\?")[0].replaceAll("/+$", "");
        if (clean.isBlank()) {
            clean = "/";
        }
        return PATH_ID_REGEX.matcher(clean).replaceAll("/{id}");
    }

    public static String canonicalKey(String method, String rawPath) {
        return method.toUpperCase().trim() + " " + normalizePath(rawPath);
    }

    public void recordStep(String sessionId, String method, String rawPath) {
        if (sessionId == null || sessionId.isBlank()) {
            return;
        }
        String stepKey = canonicalKey(method, rawPath);

        // Record in Redis if available
        if (redisTemplate != null) {
            try {
                String key = REDIS_PREFIX + sessionId;
                redisTemplate.opsForSet().add(key, stepKey);
                redisTemplate.expire(key, SESSION_TTL);
            } catch (Exception e) {
                log.debug("Redis unavailable for workflow step recording, using memory fallback: {}", e.getMessage());
            }
        }

        // Always mirror in memory store for resilient zero-latency read access
        memoryStore.computeIfAbsent(sessionId, k -> ConcurrentHashMap.newKeySet()).add(stepKey);
    }

    public Set<String> getCompletedSteps(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return Collections.emptySet();
        }

        Set<String> steps = new HashSet<>();
        if (redisTemplate != null) {
            try {
                Set<String> redisSteps = redisTemplate.opsForSet().members(REDIS_PREFIX + sessionId);
                if (redisSteps != null) {
                    steps.addAll(redisSteps);
                }
            } catch (Exception e) {
                log.debug("Redis query failed for workflow steps, falling back to memory: {}", e.getMessage());
            }
        }

        Set<String> memSteps = memoryStore.get(sessionId);
        if (memSteps != null) {
            steps.addAll(memSteps);
        }

        return steps;
    }

    public void clearSession(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return;
        }
        if (redisTemplate != null) {
            try {
                redisTemplate.delete(REDIS_PREFIX + sessionId);
            } catch (Exception ignored) {}
        }
        memoryStore.remove(sessionId);
    }

    public WorkflowCheckResult checkCompliance(
            String sessionId,
            String method,
            String rawPath,
            Collection<String> userRoles) {

        String targetEndpoint = canonicalKey(method, rawPath);
        Set<String> completedSteps = getCompletedSteps(sessionId);

        // 1. Administrative & Security Analyst roles bypass workflow sequence enforcement
        if (userRoles != null) {
            for (String role : userRoles) {
                if ("ROLE_SECURITY_ADMIN".equalsIgnoreCase(role) ||
                    "ROLE_SECURITY_ANALYST".equalsIgnoreCase(role) ||
                    "SECURITY_ADMIN".equalsIgnoreCase(role) ||
                    "SECURITY_ANALYST".equalsIgnoreCase(role)) {
                    return WorkflowCheckResult.allow(targetEndpoint, completedSteps);
                }
            }
        }

        // 2. Evaluate against active rules
        for (WorkflowRule rule : rules) {
            if (rule.matches(method, rawPath)) {
                List<String> required = rule.getRequiredPredecessors();
                boolean satisfied = false;

                for (String req : required) {
                    if (completedSteps.contains(req)) {
                        satisfied = true;
                        break;
                    }
                }

                if (!satisfied) {
                    String reason = String.format(
                        "Business workflow violation: executing '%s' requires prerequisite step in %s, but session '%s' has not completed it.",
                        targetEndpoint, required, sessionId
                    );
                    return WorkflowCheckResult.block(
                        rule.getId(),
                        targetEndpoint,
                        required,
                        completedSteps,
                        reason
                    );
                }
            }
        }

        return WorkflowCheckResult.allow(targetEndpoint, completedSteps);
    }

    public List<WorkflowRule> getRules() {
        return Collections.unmodifiableList(rules);
    }

    public void addRule(WorkflowRule rule) {
        if (rule != null) {
            rules.remove(rule);
            rules.add(rule);
        }
    }
}
