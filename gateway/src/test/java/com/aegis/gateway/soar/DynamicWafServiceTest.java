package com.aegis.gateway.soar;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class DynamicWafServiceTest {

    private DynamicWafService wafService;

    @BeforeEach
    void setUp() {
        wafService = new DynamicWafService(null);
    }

    @Test
    void testAddAndCheckBan() {
        assertThat(wafService.isBanned("203.0.113.55")).isFalse();

        WafBanRule rule = wafService.addBan("203.0.113.55", "Test Brute Force", "INC-001", Duration.ofHours(2), "TEST");
        assertThat(rule).isNotNull();
        assertThat(wafService.isBanned("203.0.113.55")).isTrue();
    }

    @Test
    void testRemoveBan() {
        WafBanRule rule = wafService.addBan("198.51.100.99", "Suspicious Probe", "INC-002", Duration.ofHours(1), "TEST");
        assertThat(wafService.isBanned("198.51.100.99")).isTrue();

        boolean removed = wafService.removeBan(rule.id());
        assertThat(removed).isTrue();
        assertThat(wafService.isBanned("198.51.100.99")).isFalse();
    }

    @Test
    void testSubnetBanMatching() {
        wafService.addBan("192.0.2.0/24", "Attacker Subnet", "INC-003", Duration.ofHours(1), "TEST");

        assertThat(wafService.isBanned("192.0.2.1")).isTrue();
        assertThat(wafService.isBanned("192.0.2.254")).isTrue();
        assertThat(wafService.isBanned("192.0.3.1")).isFalse();
    }

    @Test
    void testExportFormats() {
        wafService.addBan("203.0.113.10", "Export Test", "INC-004", Duration.ofHours(1), "TEST");

        Map<String, Object> cf = wafService.toCloudflarePayload();
        assertThat(cf.get("name")).isEqualTo("aegis_threat_null_route");
        assertThat(cf.get("items")).isNotNull();

        Map<String, Object> aws = wafService.toAwsWafIpSet();
        assertThat(aws.get("Name")).isEqualTo("AegisAutonomousIPSet");
        assertThat(aws.get("Addresses")).asList().contains("203.0.113.10/32");

        List<String> iptables = wafService.toIptablesRules();
        assertThat(iptables).isNotEmpty();
        assertThat(iptables.get(0)).contains("iptables -A INPUT -s");
    }
}
