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
 * Distributed cryptographic JWT token revocation service.
 * Tracks specific revoked token IDs (jti) and subject cutoff timestamps with sub-microsecond in-memory evaluation.
 */
@Service
public class TokenRevocationService {
    private static final Logger log = LoggerFactory.getLogger(TokenRevocationService.class);
    public static final String REDIS_REVOKE_CHANNEL = "aegis:soar:token-revocation";
    private static final String REDIS_REVOKE_KEY_PREFIX = "aegis:soar:revoked:jti:";
    private static final String REDIS_SUB_KEY_PREFIX = "aegis:soar:revoked:sub:";

    private final StringRedisTemplate redisTemplate;

    // jti -> TokenRevocationRecord
    private final Map<String, TokenRevocationRecord> revokedJtis = new ConcurrentHashMap<>();
    // subject -> cutoff Instant (tokens issued before this instant are invalid)
    private final Map<String, Instant> subjectCutoffs = new ConcurrentHashMap<>();

    @Autowired
    public TokenRevocationService(@Autowired(required = false) StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
        initSeedRevocations();
    }

    private void initSeedRevocations() {
        // Pre-seed a known compromised test token
        TokenRevocationRecord seedRecord = new TokenRevocationRecord(
                "jti-compromised-demo-token",
                "attacker.test",
                "Demonstration token theft revocation",
                Instant.now(),
                Instant.now().plus(Duration.ofHours(24))
        );
        revokedJtis.put(seedRecord.jti(), seedRecord);
    }

    public TokenRevocationRecord revokeToken(String jti, String subject, String reason, Duration ttl) {
        Instant now = Instant.now();
        Instant expiresAt = ttl != null ? now.plus(ttl) : now.plus(Duration.ofHours(24));

        TokenRevocationRecord record = new TokenRevocationRecord(
                jti != null ? jti : "jti-auto-" + UUID.randomUUID().toString().substring(0, 8),
                subject,
                reason != null ? reason : "Autonomous token revocation on threat detection",
                now,
                expiresAt
        );

        revokedJtis.put(record.jti(), record);
        log.warn("JWT Revoked: [JTI={}] for subject '{}', reason: '{}' until {}", record.jti(), subject, reason, expiresAt);

        // Broadcast to cluster via Redis Pub/Sub & Key-Value
        if (redisTemplate != null) {
            try {
                String key = REDIS_REVOKE_KEY_PREFIX + record.jti();
                redisTemplate.opsForValue().set(key, record.subject() != null ? record.subject() : "anonymous", ttl != null ? ttl : Duration.ofHours(24));
                redisTemplate.convertAndSend(REDIS_REVOKE_CHANNEL, record.jti() + ":" + record.subject());
            } catch (Exception e) {
                log.debug("Redis unavailable for token revocation publish: {}", e.getMessage());
            }
        }

        return record;
    }

    public void revokeSubject(String subject, String reason, Duration retention) {
        if (subject == null || subject.isBlank()) {
            return;
        }
        Instant cutoff = Instant.now();
        subjectCutoffs.put(subject, cutoff);
        log.warn("Subject Tokens Revoked: user '{}' cutoff set to {}, reason: '{}'", subject, cutoff, reason);

        if (redisTemplate != null) {
            try {
                String key = REDIS_SUB_KEY_PREFIX + subject;
                redisTemplate.opsForValue().set(key, String.valueOf(cutoff.toEpochMilli()), retention != null ? retention : Duration.ofHours(24));
                redisTemplate.convertAndSend(REDIS_REVOKE_CHANNEL, "SUB:" + subject + ":" + cutoff.toEpochMilli());
            } catch (Exception e) {
                log.debug("Redis unavailable for subject revocation publish: {}", e.getMessage());
            }
        }
    }

    public boolean isRevoked(String jti, String subject, Instant issuedAt) {
        // 1. Check JTI denylist
        if (jti != null && !jti.isBlank()) {
            TokenRevocationRecord record = revokedJtis.get(jti);
            if (record != null) {
                if (record.isExpired()) {
                    revokedJtis.remove(jti);
                } else {
                    return true;
                }
            }

            // Fallback check against Redis
            if (redisTemplate != null) {
                try {
                    if (Boolean.TRUE.equals(redisTemplate.hasKey(REDIS_REVOKE_KEY_PREFIX + jti))) {
                        return true;
                    }
                } catch (Exception ignored) {}
            }
        }

        // 2. Check Subject cutoff
        if (subject != null && !subject.isBlank() && issuedAt != null) {
            Instant cutoff = subjectCutoffs.get(subject);
            if (cutoff != null && issuedAt.isBefore(cutoff)) {
                return true;
            }

            // Fallback check against Redis
            if (redisTemplate != null) {
                try {
                    String cutoffStr = redisTemplate.opsForValue().get(REDIS_SUB_KEY_PREFIX + subject);
                    if (cutoffStr != null) {
                        long cutoffMillis = Long.parseLong(cutoffStr);
                        if (issuedAt.toEpochMilli() < cutoffMillis) {
                            return true;
                        }
                    }
                } catch (Exception ignored) {}
            }
        }

        return false;
    }

    public List<TokenRevocationRecord> getRevokedTokens() {
        return revokedJtis.values().stream()
                .filter(r -> !r.isExpired())
                .sorted(Comparator.comparing(TokenRevocationRecord::revokedAt).reversed())
                .collect(Collectors.toList());
    }

    public Map<String, Instant> getSubjectCutoffs() {
        return Collections.unmodifiableMap(subjectCutoffs);
    }
}
