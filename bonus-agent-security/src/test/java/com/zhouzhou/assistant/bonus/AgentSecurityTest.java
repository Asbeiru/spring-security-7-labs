package com.zhouzhou.assistant.bonus;

import java.time.*;
import java.util.*;
import java.util.concurrent.*;
import org.junit.jupiter.api.*;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.*;
import org.springframework.security.concurrent.DelegatingSecurityContextCallable;
import static com.zhouzhou.assistant.bonus.AgentSecurity.*;
import static org.assertj.core.api.Assertions.*;

class AgentSecurityTest {
    static final Instant NOW = Instant.parse("2026-10-25T08:00:00Z");
    static final class MutableClock extends Clock {
        Instant now = NOW;
        @Override public java.time.ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(java.time.ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }
    MutableClock clock; Registry registry; Approvals approvals; Gateway gateway;
    Grant root;
    @BeforeEach void setup() {
        clock = new MutableClock(); registry = new Registry(clock); approvals = new Approvals(clock); gateway = new Gateway(registry, approvals);
        root = grant("root", null, "main", "acme", Set.of("documents.read", "expenses.submit"), Set.of("brief-a", "expense-a", "brief-b"), NOW.plusSeconds(600));
        registry.seed(root); login("main", "root");
    }
    @AfterEach void clean() { SecurityContextHolder.clearContext(); }
    Grant grant(String id, String parent, String actor, String tenant, Set<String> actions, Set<String> resources, Instant expires) {
        return new Grant(id, parent, "alice", actor, "weekly-report", tenant, actions, resources, expires);
    }
    static void login(String actor, String grant) {
        SecurityContext c = SecurityContextHolder.createEmptyContext(); c.setAuthentication(new DelegationAuthenticationToken(new Identity(actor, grant))); SecurityContextHolder.setContext(c);
    }
    ToolCall expense(int amount) { return new ToolCall("expenses.submit", "expense-a", "acme", amount); }
    void denied(Runnable run) { int before = gateway.effects(); assertThatThrownBy(run::run).isInstanceOf(AccessDeniedException.class); assertThat(gateway.effects()).isEqualTo(before); }
    org.springframework.security.core.Authentication approver(String name) {
        return UsernamePasswordAuthenticationToken.authenticated(name, "", List.of(new SimpleGrantedAuthority("ROLE_APPROVER")));
    }
    @Test void allowedReadAndSmallExpenseExecute() {
        assertThat(gateway.execute(new ToolCall("documents.read", "brief-a", "acme", 0), null).status()).isEqualTo("EXECUTED");
        gateway.execute(expense(50), null); assertThat(gateway.effects()).isEqualTo(1);
    }
    @Test void wrongResourceTypeAndOversizedExpenseHaveNoEffects() {
        denied(() -> gateway.execute(new ToolCall("expenses.submit", "brief-a", "acme", 50), null));
        denied(() -> gateway.execute(expense(501), null));
    }
    @Test void unknownActionHasNoEffects() { denied(() -> gateway.execute(new ToolCall("expenses.delete", "expense-a", "acme", 50), null)); }
    @Test void callerTenantStringCannotOverrideResourceOwner() { denied(() -> gateway.execute(new ToolCall("documents.read", "brief-b", "acme", 0), null)); }
    @Test void unknownResourceFailsClosed() { denied(() -> gateway.execute(new ToolCall("documents.read", "absent", "acme", 0), null)); }
    @Test void actorCannotBorrowAnotherGrant() { login("intruder", "root"); denied(() -> gateway.execute(expense(50), null)); }
    @Test void childCanNarrowButCannotExpandActionsResourcesTenantOrLifetime() {
        Grant child = grant("child", "root", "sub", "acme", Set.of("documents.read"), Set.of("brief-a"), NOW.plusSeconds(100));
        registry.delegate("root", child); login("sub", "child");
        assertThat(gateway.execute(new ToolCall("documents.read", "brief-a", "acme", 0), null).status()).isEqualTo("EXECUTED");
        denied(() -> gateway.execute(expense(50), null));
        assertThatThrownBy(() -> registry.delegate("child", grant("expanded", "child", "sub2", "acme", Set.of("expenses.submit"), Set.of("brief-a"), NOW.plusSeconds(90)))).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> registry.delegate("child", grant("resource", "child", "sub2", "acme", Set.of("documents.read"), Set.of("brief-b"), NOW.plusSeconds(90)))).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> registry.delegate("child", grant("tenant", "child", "sub2", "other", child.actions(), child.resources(), NOW.plusSeconds(90)))).isInstanceOf(AccessDeniedException.class);
        assertThatThrownBy(() -> registry.delegate("child", grant("time", "child", "sub2", "acme", child.actions(), child.resources(), NOW.plusSeconds(200)))).isInstanceOf(AccessDeniedException.class);
    }
    @Test void revokedParentInvalidatesLiveChild() {
        registry.delegate("root", grant("child", "root", "sub", "acme", Set.of("documents.read"), Set.of("brief-a"), NOW.plusSeconds(100)));
        registry.revoke("root"); login("sub", "child"); denied(() -> gateway.execute(new ToolCall("documents.read", "brief-a", "acme", 0), null));
    }
    @Test void expiredDelegationHasNoEffects() { clock.now = NOW.plusSeconds(601); denied(() -> gateway.execute(expense(50), null)); }
    @Test void directPolicyToolIsDeniedEvenWithoutHttp() { denied(() -> gateway.execute(new ToolCall("policy.update", "expense-a", "acme", 0), null)); }
    @Test void highRiskWaitsAndUnapprovedTicketCannotExecute() {
        var pending = gateway.execute(expense(200), null); assertThat(pending.status()).isEqualTo("PENDING");
        assertThat(gateway.effects()).isZero(); denied(() -> gateway.execute(expense(200), pending.ticket()));
    }
    @Test void approvalBindsParametersAndIsConsumedOnce() {
        UUID id = gateway.execute(expense(200), null).ticket(); approvals.decide(id, approver("manager"), true);
        denied(() -> gateway.execute(expense(201), id));
        gateway.execute(expense(200), id); assertThat(gateway.effects()).isEqualTo(1);
        denied(() -> gateway.execute(expense(200), id));
    }
    @Test void approvalResumeCannotSkipBindingByDowngradingAmountOrSwitchingAction() {
        UUID id = gateway.execute(expense(200), null).ticket(); approvals.decide(id, approver("manager"), true);
        denied(() -> gateway.execute(expense(50), id));
        denied(() -> gateway.execute(new ToolCall("documents.read", "brief-a", "acme", 0), id));
        gateway.execute(expense(200), id);
        denied(() -> gateway.execute(expense(50), id));
        gateway.execute(expense(50), null); // An independent ordinary request still has its own authorization.
        assertThat(gateway.effects()).isEqualTo(2);
    }
    @Test void agentsAndOriginatorCannotApprove() {
        UUID id = gateway.execute(expense(200), null).ticket();
        denied(() -> approvals.decide(id, SecurityContextHolder.getContext().getAuthentication(), true));
        denied(() -> approvals.decide(id, approver("alice"), true));
    }
    @Test void rejectedAndExpiredApprovalsCannotExecute() {
        UUID rejected = gateway.execute(expense(200), null).ticket(); approvals.decide(rejected, approver("manager"), false);
        denied(() -> gateway.execute(expense(200), rejected));
        UUID expired = gateway.execute(expense(200), null).ticket(); approvals.decide(expired, approver("manager"), true);
        clock.now = NOW.plusSeconds(301); denied(() -> gateway.execute(expense(200), expired));
    }
    @Test void delegationRecheckedAfterApproval() {
        UUID id = gateway.execute(expense(200), null).ticket(); approvals.decide(id, approver("manager"), true);
        registry.revoke("root"); denied(() -> gateway.execute(expense(200), id));
    }
    @Test void reflectionOnPublicGatewayStillChecksIdentity() throws Exception {
        SecurityContextHolder.clearContext();
        var method = Gateway.class.getMethod("execute", ToolCall.class, UUID.class);
        assertThatThrownBy(() -> method.invoke(gateway, expense(50), null)).hasCauseInstanceOf(AccessDeniedException.class);
        assertThat(gateway.effects()).isZero();
    }
    @Test void plainVirtualThreadAndPoolDoNotInheritDefaultThreadLocal() throws Exception {
        assertThat(SecurityContextHolder.getContextHolderStrategy().getClass().getSimpleName()).isEqualTo("ThreadLocalSecurityContextHolderStrategy");
        try (var virtual = Executors.newVirtualThreadPerTaskExecutor(); var pool = Executors.newSingleThreadExecutor()) {
            assertThat(virtual.submit(() -> SecurityContextHolder.getContext().getAuthentication()).get()).isNull();
            assertThat(pool.submit(() -> SecurityContextHolder.getContext().getAuthentication()).get()).isNull();
        }
    }
    @Test void capturedContextsStayDistinctAndPoolIsCleanAfterException() throws Exception {
        try (var virtual = Executors.newVirtualThreadPerTaskExecutor(); var pool = Executors.newSingleThreadExecutor()) {
            var futures = new ArrayList<Future<String>>();
            for (int i = 0; i < 40; i++) {
                String expected = "agent-" + i; login(expected, "unused");
                Callable<String> task = new DelegatingSecurityContextCallable<>(() -> {
                    assertThat(SecurityContextHolder.getContext().getAuthentication().getName()).isEqualTo(expected); return expected;
                });
                futures.add((i % 2 == 0 ? virtual : pool).submit(task));
            }
            for (int i = 0; i < futures.size(); i++) assertThat(futures.get(i).get()).isEqualTo("agent-" + i);
            Callable<String> failed = new DelegatingSecurityContextCallable<>(() -> { throw new IllegalStateException("fixture"); });
            assertThatThrownBy(() -> pool.submit(failed).get()).isInstanceOf(ExecutionException.class);
            assertThat(pool.submit(() -> SecurityContextHolder.getContext().getAuthentication()).get()).isNull();
        }
    }
    @Test void asynchronousGatewayAndConcurrentApprovalReplayHaveOneEffect() throws Exception {
        UUID id = gateway.execute(expense(200), null).ticket(); approvals.decide(id, approver("manager"), true);
        try (var executor = Executors.newVirtualThreadPerTaskExecutor()) {
            var tasks = new ArrayList<Callable<Boolean>>();
            for (int i = 0; i < 8; i++) tasks.add(new DelegatingSecurityContextCallable<>(() -> {
                try { gateway.execute(expense(200), id); return true; } catch (AccessDeniedException ex) { return false; }
            }));
            int successful = 0; for (var f : executor.invokeAll(tasks)) if (f.get()) successful++;
            assertThat(successful).isEqualTo(1); assertThat(gateway.effects()).isEqualTo(1);
        }
    }
}
