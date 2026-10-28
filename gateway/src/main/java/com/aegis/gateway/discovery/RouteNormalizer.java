package com.aegis.gateway.discovery;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.regex.Pattern;

/**
 * Conservative route normalizer and service resolver for Aegis Telemetry-Based API Discovery.
 * Transforms concrete resource identifiers into normalized parameter templates without guessing,
 * strips query parameters/credentials, and maps routes to downstream service boundaries.
 */
public final class RouteNormalizer {

    private static final Pattern QUERY_STRING_PATTERN = Pattern.compile("\\?.*$");
    private static final Pattern MULTI_SLASH_PATTERN = Pattern.compile("/{2,}");
    private static final Pattern UUID_PATTERN = Pattern.compile("(?i)[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}");
    private static final Pattern REF_PATTERN = Pattern.compile("(ACCT|CUST|SYNTH|TX)-[a-zA-Z0-9_-]+");

    // Semantic route templates for known domain endpoints
    private static final Pattern CUSTOMER_PROFILE_PATTERN = Pattern.compile("^(/api/v1)?/customers/([^/]+)/profile$");
    private static final Pattern CUSTOMER_BY_ID_PATTERN = Pattern.compile("^(/api/v1)?/customers/([^/]+)$");

    private static final Pattern ACCOUNT_BALANCE_PATTERN = Pattern.compile("^(/api/v1)?/accounts/([^/]+)/balance$");
    private static final Pattern ACCOUNT_DEBIT_PATTERN = Pattern.compile("^(/api/v1)?/accounts/([^/]+)/debit$");
    private static final Pattern ACCOUNT_BY_ID_PATTERN = Pattern.compile("^(/api/v1)?/accounts/([^/]+)$");

    private static final Pattern BENEFICIARY_VERIFY_PATTERN = Pattern.compile("^(/api/v1)?/beneficiaries/([^/]+)/verify$");
    private static final Pattern BENEFICIARY_BY_ID_PATTERN = Pattern.compile("^(/api/v1)?/beneficiaries/([^/]+)$");

    private static final Pattern TRANSACTION_BY_ID_PATTERN = Pattern.compile("^(/api/v1)?/transactions/([^/]+)$");

    private static final Pattern SECURITY_INCIDENT_SUBRESOURCE_PATTERN = Pattern.compile("^(/api/v1)?/security/incidents/([^/]+)/(evidence|history|status|policy-decisions)$");
    private static final Pattern SECURITY_INCIDENT_BY_ID_PATTERN = Pattern.compile("^(/api/v1)?/security/incidents/([^/]+)$");
    private static final Pattern SECURITY_EVENT_BY_ID_PATTERN = Pattern.compile("^(/api/v1)?/security/events/([^/]+)$");

    private RouteNormalizer() {
        // Utility class
    }

    /**
     * Normalizes a raw request URI or route identifier into a safe route template.
     * Strips query strings, resolves known parameter slots, and normalizes UUIDs/references.
     */
    public static String normalize(String uri) {
        if (uri == null || uri.isBlank()) {
            return "/";
        }

        // 1. Strip query string, trailing fragment, and trim
        String clean = uri.trim();
        clean = QUERY_STRING_PATTERN.matcher(clean).replaceAll("");
        if (clean.contains("#")) {
            clean = clean.substring(0, clean.indexOf('#'));
        }
        clean = MULTI_SLASH_PATTERN.matcher(clean).replaceAll("/");
        if (clean.endsWith("/") && clean.length() > 1) {
            clean = clean.substring(0, clean.length() - 1);
        }

        // 2. Domain-specific semantic route normalization
        var custProfileMatcher = CUSTOMER_PROFILE_PATTERN.matcher(clean);
        if (custProfileMatcher.matches()) {
            String prefix = custProfileMatcher.group(1) != null ? custProfileMatcher.group(1) : "";
            return prefix + "/customers/{customerId}/profile";
        }

        var custMatcher = CUSTOMER_BY_ID_PATTERN.matcher(clean);
        if (custMatcher.matches()) {
            String prefix = custMatcher.group(1) != null ? custMatcher.group(1) : "";
            String segment = custMatcher.group(2);
            if (isIdentifierSegment(segment)) {
                return prefix + "/customers/{customerId}";
            }
        }

        var acctBalanceMatcher = ACCOUNT_BALANCE_PATTERN.matcher(clean);
        if (acctBalanceMatcher.matches()) {
            String prefix = acctBalanceMatcher.group(1) != null ? acctBalanceMatcher.group(1) : "";
            return prefix + "/accounts/{accountId}/balance";
        }

        var acctDebitMatcher = ACCOUNT_DEBIT_PATTERN.matcher(clean);
        if (acctDebitMatcher.matches()) {
            String prefix = acctDebitMatcher.group(1) != null ? acctDebitMatcher.group(1) : "";
            return prefix + "/accounts/{accountId}/debit";
        }

        var acctMatcher = ACCOUNT_BY_ID_PATTERN.matcher(clean);
        if (acctMatcher.matches()) {
            String prefix = acctMatcher.group(1) != null ? acctMatcher.group(1) : "";
            String segment = acctMatcher.group(2);
            if (isIdentifierSegment(segment)) {
                return prefix + "/accounts/{accountId}";
            }
        }

        var benVerifyMatcher = BENEFICIARY_VERIFY_PATTERN.matcher(clean);
        if (benVerifyMatcher.matches()) {
            String prefix = benVerifyMatcher.group(1) != null ? benVerifyMatcher.group(1) : "";
            return prefix + "/beneficiaries/{beneficiaryId}/verify";
        }

        var benMatcher = BENEFICIARY_BY_ID_PATTERN.matcher(clean);
        if (benMatcher.matches()) {
            String prefix = benMatcher.group(1) != null ? benMatcher.group(1) : "";
            String segment = benMatcher.group(2);
            if (isIdentifierSegment(segment)) {
                return prefix + "/beneficiaries/{beneficiaryId}";
            }
        }

        var txMatcher = TRANSACTION_BY_ID_PATTERN.matcher(clean);
        if (txMatcher.matches()) {
            String prefix = txMatcher.group(1) != null ? txMatcher.group(1) : "";
            String segment = txMatcher.group(2);
            if (isIdentifierSegment(segment)) {
                return prefix + "/transactions/{transactionId}";
            }
        }

        var incidentSubMatcher = SECURITY_INCIDENT_SUBRESOURCE_PATTERN.matcher(clean);
        if (incidentSubMatcher.matches()) {
            String prefix = incidentSubMatcher.group(1) != null ? incidentSubMatcher.group(1) : "";
            String sub = incidentSubMatcher.group(3);
            return prefix + "/security/incidents/{incidentId}/" + sub;
        }

        var incidentMatcher = SECURITY_INCIDENT_BY_ID_PATTERN.matcher(clean);
        if (incidentMatcher.matches()) {
            String prefix = incidentMatcher.group(1) != null ? incidentMatcher.group(1) : "";
            String segment = incidentMatcher.group(2);
            if (isIdentifierSegment(segment)) {
                return prefix + "/security/incidents/{incidentId}";
            }
        }

        var eventMatcher = SECURITY_EVENT_BY_ID_PATTERN.matcher(clean);
        if (eventMatcher.matches()) {
            String prefix = eventMatcher.group(1) != null ? eventMatcher.group(1) : "";
            String segment = eventMatcher.group(2);
            if (isIdentifierSegment(segment)) {
                return prefix + "/security/events/{eventId}";
            }
        }

        // 3. Fallback: replace UUIDs and known reference patterns safely
        String normalized = UUID_PATTERN.matcher(clean).replaceAll("{id}");
        normalized = REF_PATTERN.matcher(normalized).replaceAll("{ref}");

        return normalized;
    }

    /**
     * Resolves the downstream service boundary name based on route template.
     */
    public static String resolveService(String routeTemplate) {
        if (routeTemplate == null || routeTemplate.isBlank()) {
            return "unknown";
        }
        String path = routeTemplate.toLowerCase();
        if (path.startsWith("/api/v1/customers") || path.startsWith("/customers")) {
            return "customer-service";
        }
        if (path.startsWith("/api/v1/accounts") || path.startsWith("/accounts")) {
            return "account-service";
        }
        if (path.startsWith("/api/v1/beneficiaries") || path.startsWith("/beneficiaries")
                || path.startsWith("/api/v1/transactions") || path.startsWith("/transactions")
                || path.startsWith("/api/v1/transfers") || path.startsWith("/transfers")) {
            return "transaction-service";
        }
        if (path.startsWith("/api/v1/security") || path.startsWith("/security")) {
            return "security-gateway";
        }
        if (path.startsWith("/actuator")) {
            return "aegis-gateway";
        }
        return "external-gateway";
    }

    /**
     * Generates a deterministic, stable endpoint identifier.
     */
    public static String generateEndpointId(String httpMethod, String routeTemplate) {
        String method = httpMethod != null ? httpMethod.toUpperCase().trim() : "GET";
        String template = routeTemplate != null ? routeTemplate.trim() : "/";
        String rawKey = method + ":" + template;
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(rawKey.getBytes(StandardCharsets.UTF_8));
            return "ep_" + HexFormat.of().formatHex(hash).substring(0, 16);
        } catch (NoSuchAlgorithmException e) {
            // SHA-256 is guaranteed in Java runtime
            return "ep_" + Integer.toHexString(rawKey.hashCode());
        }
    }

    private static boolean isIdentifierSegment(String segment) {
        if (segment == null || segment.isBlank()) {
            return false;
        }
        // Is it already a placeholder?
        if (segment.startsWith("{") && segment.endsWith("}")) {
            return true;
        }
        // UUID?
        if (UUID_PATTERN.matcher(segment).matches()) {
            return true;
        }
        // ACCT-, CUST-, SYNTH-, TX-?
        if (REF_PATTERN.matcher(segment).matches()) {
            return true;
        }
        // Numeric sequence (e.g. 1001, 1234567)?
        if (segment.matches("^\\d+$")) {
            return true;
        }
        return false;
    }
}
