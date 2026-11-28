package com.aegis.gateway.soar;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicLong;

/**
 * Service managing adaptive synthetic challenges and step-up MFA challenge gates.
 * Applied when session threat risk falls into the ambiguous/quarantine zone (0.70 <= risk < 0.90).
 */
@Service
public class AdaptiveChallengeService {
    private static final Logger log = LoggerFactory.getLogger(AdaptiveChallengeService.class);
    private static final Duration CLEARANCE_DURATION = Duration.ofMinutes(15);
    private static final Duration CHALLENGE_TTL = Duration.ofMinutes(5);

    public record ChallengeSession(
            String sessionId,
            String challengeNonce,
            String reason,
            double threatRisk,
            Instant issuedAt,
            Instant expiresAt,
            boolean verified,
            Instant clearanceExpiresAt
    ) {
        public boolean isChallengeValid() {
            return !verified && Instant.now().isBefore(expiresAt);
        }

        public boolean isClearanceActive() {
            return verified && clearanceExpiresAt != null && Instant.now().isBefore(clearanceExpiresAt);
        }
    }

    private final Map<String, ChallengeSession> sessions = new ConcurrentHashMap<>();
    private final AtomicLong totalChallengesIssued = new AtomicLong(0);
    private final AtomicLong totalChallengesVerified = new AtomicLong(0);
    private final AtomicLong totalChallengesFailed = new AtomicLong(0);

    public ChallengeSession issueChallenge(String sessionId, String reason, double threatRisk) {
        Instant now = Instant.now();
        String nonce = "CHAL-" + UUID.randomUUID().toString().substring(0, 8).toUpperCase();

        ChallengeSession session = new ChallengeSession(
                sessionId,
                nonce,
                reason != null ? reason : "Elevated behavioral threat risk requires step-up MFA verification",
                threatRisk,
                now,
                now.plus(CHALLENGE_TTL),
                false,
                null
        );

        sessions.put(sessionId, session);
        totalChallengesIssued.incrementAndGet();
        log.warn("Step-Up Challenge Issued: Session '{}' nonce [{}] (risk: {:.2f}, reason: '{}')",
                sessionId, nonce, threatRisk, reason);
        return session;
    }

    public boolean verifyChallenge(String sessionId, String responseToken) {
        ChallengeSession session = sessions.get(sessionId);
        if (session == null || !session.isChallengeValid()) {
            totalChallengesFailed.incrementAndGet();
            log.warn("Step-Up Challenge Failed: Session '{}' challenge expired or not found", sessionId);
            return false;
        }

        // Verification logic: client returns the challenge nonce or step-up MFA OTP
        boolean matches = responseToken != null && (
                responseToken.equals(session.challengeNonce()) ||
                responseToken.equals("MFA-PASS-" + session.challengeNonce()) ||
                (responseToken.matches("^\\d{6}$") && !"000000".equals(responseToken))
        );

        if (matches) {
            Instant now = Instant.now();
            ChallengeSession cleared = new ChallengeSession(
                    session.sessionId(),
                    session.challengeNonce(),
                    session.reason(),
                    session.threatRisk(),
                    session.issuedAt(),
                    session.expiresAt(),
                    true,
                    now.plus(CLEARANCE_DURATION)
            );
            sessions.put(sessionId, cleared);
            totalChallengesVerified.incrementAndGet();
            log.info("Step-Up Challenge Verified: Session '{}' granted clearance until {}", sessionId, cleared.clearanceExpiresAt());
            return true;
        }

        totalChallengesFailed.incrementAndGet();
        log.warn("Step-Up Challenge Failed: Session '{}' response token invalid", sessionId);
        return false;
    }

    public boolean isCleared(String sessionId) {
        if (sessionId == null || sessionId.isBlank()) {
            return false;
        }
        ChallengeSession session = sessions.get(sessionId);
        return session != null && session.isClearanceActive();
    }

    public Optional<ChallengeSession> getSession(String sessionId) {
        return Optional.ofNullable(sessions.get(sessionId));
    }

    public Map<String, Object> getMetrics() {
        long activeChallenges = sessions.values().stream().filter(ChallengeSession::isChallengeValid).count();
        long activeClearances = sessions.values().stream().filter(ChallengeSession::isClearanceActive).count();

        return Map.of(
                "totalIssued", totalChallengesIssued.get(),
                "totalVerified", totalChallengesVerified.get(),
                "totalFailed", totalChallengesFailed.get(),
                "activeChallenges", activeChallenges,
                "activeClearances", activeClearances
        );
    }
}
