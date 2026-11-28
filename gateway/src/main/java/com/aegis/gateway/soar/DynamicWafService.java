package com.aegis.gateway.soar;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

/**
 * Service managing dynamic edge WAF null-routing and IP blocklist synchronization.
 * Supports autonomous ban registration and exports to Cloudflare, AWS WAF, and iptables.
 */
@Service
public class DynamicWafService {
    private static final Logger log = LoggerFactory.getLogger(DynamicWafService.class);
    private static final String REDIS_BAN_PREFIX = "aegis:soar:waf:ban:";

    private final StringRedisTemplate redisTemplate;
    private final Map<String, WafBanRule> activeBans = new ConcurrentHashMap<>();

    @Autowired
    public DynamicWafService(@Autowired(required = false) StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
        initDefaultBans();
    }

    private void initDefaultBans() {
        // Pre-seed known malicious proxy test range for demonstration & tests
        WafBanRule defaultRule = new WafBanRule(
                "BAN-SEED-001",
                "198.51.100.24",
                "Automated high-rate credential stuffing campaign",
                "INC-TEST-001",
                Instant.now(),
                Instant.now().plus(Duration.ofDays(7)),
                "AUTONOMOUS_POLICY",
                true
        );
        activeBans.put(defaultRule.id(), defaultRule);
    }

    public WafBanRule addBan(String ipOrCidr, String reason, String incidentId, Duration ttl, String source) {
        String banId = "BAN-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();
        Instant now = Instant.now();
        Instant expiresAt = ttl != null ? now.plus(ttl) : now.plus(Duration.ofDays(1));

        WafBanRule rule = new WafBanRule(
                banId,
                ipOrCidr.trim(),
                reason != null ? reason : "Autonomous SOAR threat mitigation",
                incidentId,
                now,
                expiresAt,
                source != null ? source : "AUTONOMOUS_SOAR",
                true
        );

        activeBans.put(banId, rule);
        log.warn("Dynamic WAF Ban Applied: [{}] {} for reason: '{}' until {}", banId, ipOrCidr, reason, expiresAt);

        // Mirror to Redis if available
        if (redisTemplate != null) {
            try {
                String key = REDIS_BAN_PREFIX + ipOrCidr.trim();
                redisTemplate.opsForValue().set(key, banId, ttl != null ? ttl : Duration.ofDays(1));
            } catch (Exception e) {
                log.debug("Redis unavailable for WAF ban sync: {}", e.getMessage());
            }
        }

        return rule;
    }

    public boolean removeBan(String banId) {
        WafBanRule rule = activeBans.remove(banId);
        if (rule != null) {
            if (redisTemplate != null) {
                try {
                    redisTemplate.delete(REDIS_BAN_PREFIX + rule.ipOrCidr());
                } catch (Exception ignored) {}
            }
            log.info("Dynamic WAF Ban Revoked: [{}] for {}", banId, rule.ipOrCidr());
            return true;
        }
        return false;
    }

    public boolean isBanned(String ip) {
        if (ip == null || ip.isBlank()) {
            return false;
        }
        String cleanIp = ip.trim();

        // 1. Fast Redis lookup if configured
        if (redisTemplate != null) {
            try {
                Boolean exists = redisTemplate.hasKey(REDIS_BAN_PREFIX + cleanIp);
                if (Boolean.TRUE.equals(exists)) {
                    return true;
                }
            } catch (Exception ignored) {}
        }

        // 2. Memory collection scan with expiration cleanup
        for (Iterator<Map.Entry<String, WafBanRule>> it = activeBans.entrySet().iterator(); it.hasNext(); ) {
            WafBanRule rule = it.next().getValue();
            if (rule.isExpired()) {
                it.remove();
                continue;
            }
            if (rule.active() && matchesIp(rule.ipOrCidr(), cleanIp)) {
                return true;
            }
        }

        return false;
    }

    public List<WafBanRule> getActiveBans() {
        return activeBans.values().stream()
                .filter(b -> !b.isExpired())
                .sorted(Comparator.comparing(WafBanRule::bannedAt).reversed())
                .collect(Collectors.toList());
    }

    public Map<String, Object> toCloudflarePayload() {
        List<Map<String, String>> items = getActiveBans().stream()
                .map(b -> Map.of(
                        "ip", b.ipOrCidr(),
                        "comment", b.reason() + " (Aegis " + b.id() + ")"
                ))
                .collect(Collectors.toList());

        return Map.of(
                "kind", "ip_list",
                "name", "aegis_threat_null_route",
                "description", "Aegis autonomous edge threat blocklist",
                "items", items
        );
    }

    public Map<String, Object> toAwsWafIpSet() {
        List<String> addresses = getActiveBans().stream()
                .map(b -> b.ipOrCidr().contains("/") ? b.ipOrCidr() : b.ipOrCidr() + "/32")
                .collect(Collectors.toList());

        return Map.of(
                "Name", "AegisAutonomousIPSet",
                "Scope", "REGIONAL",
                "IPAddressVersion", "IPV4",
                "Addresses", addresses,
                "Description", "Synchronized automatically by Aegis Autonomous SOAR Engine"
        );
    }

    public List<String> toIptablesRules() {
        return getActiveBans().stream()
                .map(b -> String.format("iptables -A INPUT -s %s -j DROP # %s (%s)", b.ipOrCidr(), b.reason(), b.id()))
                .collect(Collectors.toList());
    }

    private boolean matchesIp(String ruleCidr, String clientIp) {
        if (ruleCidr.equals(clientIp)) {
            return true;
        }
        if (ruleCidr.contains("/")) {
            try {
                String[] parts = ruleCidr.split("/");
                String base = parts[0];
                int prefix = Integer.parseInt(parts[1]);
                if (prefix == 24) {
                    String basePrefix = base.substring(0, base.lastIndexOf('.'));
                    String clientPrefix = clientIp.substring(0, clientIp.lastIndexOf('.'));
                    return basePrefix.equals(clientPrefix);
                }
            } catch (Exception ignored) {}
        }
        return false;
    }
}
