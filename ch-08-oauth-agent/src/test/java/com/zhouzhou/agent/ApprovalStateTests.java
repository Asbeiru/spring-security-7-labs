package com.zhouzhou.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;
import java.time.*;
import java.util.ArrayList;
import java.util.concurrent.*;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.context.SecurityContextHolder;
import com.zhouzhou.agent.approval.ApprovalService;
import com.zhouzhou.agent.approval.ApprovalService.Binding;
import com.zhouzhou.agent.security.TrustedIdentity;

class ApprovalStateTests {
    @AfterEach
    void clear() {
        SecurityContextHolder.clearContext();
    }

    static Binding binding(String issuer, String tenant) {
        return new Binding(new TrustedIdentity(issuer, tenant, "alice", "vault-agent"), "transfer", "args");
    }

    static void bob() {
        VaultAgentSecurityTests.runAs("tenant-a", "bob", "ROLE_RISK_APPROVER");
    }

    @Test
    void sameSubjectInAnotherTenantOrIssuerCannotConsumeApproval() {
        ApprovalService service = new ApprovalService();
        Binding original = binding(VaultAgentSecurityTests.ISSUER, "tenant-a");
        String id = service.requireApproval(original, "ACC-A001,100").orElseThrow().id();
        bob();
        service.approve(id);
        assertThat(service.requireApproval(binding(VaultAgentSecurityTests.ISSUER, "tenant-b"), "same")).isPresent();
        assertThat(service.requireApproval(binding("https://other.example", "tenant-a"), "same")).isPresent();
        assertThat(service.requireApproval(original, "same")).isEmpty();
    }

    @Test
    void anApprovedTicketExpiresAtItsDeadline() {
        MutableClock clock = new MutableClock();
        ApprovalService service = new ApprovalService(clock);
        Binding binding = binding(VaultAgentSecurityTests.ISSUER, "tenant-a");
        String id = service.requireApproval(binding, "args").orElseThrow().id();
        bob();
        service.approve(id);
        clock.now = clock.now.plus(Duration.ofMinutes(15));
        assertThat(service.requireApproval(binding, "args").orElseThrow().id()).isNotEqualTo(id);
    }

    @Test
    void pendingTicketCannotBeApprovedAfterExpiry() {
        MutableClock clock = new MutableClock();
        ApprovalService service = new ApprovalService(clock);
        String id = service.requireApproval(binding(VaultAgentSecurityTests.ISSUER, "tenant-a"), "args").orElseThrow().id();
        clock.now = clock.now.plus(Duration.ofMinutes(15));
        bob();
        assertThrows(AccessDeniedException.class, () -> service.approve(id));
    }

    @Test
    void onlyOneConcurrentCallerConsumesTheApproval() throws Exception {
        ApprovalService service = new ApprovalService();
        Binding binding = binding(VaultAgentSecurityTests.ISSUER, "tenant-a");
        String id = service.requireApproval(binding, "args").orElseThrow().id();
        bob();
        service.approve(id);
        try (ExecutorService pool = Executors.newFixedThreadPool(8)) {
            CountDownLatch start = new CountDownLatch(1);
            var results = new ArrayList<Future<Boolean>>();
            for (int i = 0; i < 8; i++) {
                results.add(pool.submit(() -> { start.await(); return service.requireApproval(binding, "args").isEmpty(); }));
            }
            start.countDown();
            int granted = 0;
            for (Future<Boolean> result : results) {
                if (result.get(5, TimeUnit.SECONDS)) {
                    granted++;
                }
            }
            assertThat(granted).isEqualTo(1);
        }
    }

    static class MutableClock extends Clock {
        Instant now = Instant.parse("2026-11-06T00:00:00Z");
        public ZoneId getZone() { return ZoneOffset.UTC; }
        public Clock withZone(ZoneId zone) { return this; }
        public Instant instant() { return this.now; }
    }
}
