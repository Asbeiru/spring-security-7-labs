package com.zhouzhou.assistant.bonus;

import java.time.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authorization.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.access.AccessDeniedException;

/** Deterministic fixture. No model, credentials, remote tools or production persistence. */
public final class AgentSecurity {
    private AgentSecurity() {}
    public record Grant(String id, String parent, String originator, String actor, String task,
            String tenant, Set<String> actions, Set<String> resources, Instant expires) {
        public Grant { actions = Set.copyOf(actions); resources = Set.copyOf(resources); }
    }
    public record Identity(String actor, String grantId) {}
    public static final class DelegationAuthenticationToken extends AbstractAuthenticationToken {
        private final Identity identity;
        // Package-private: a trusted ingress must authenticate actor before creating this token.
        DelegationAuthenticationToken(Identity identity) { super(List.of()); this.identity = identity; super.setAuthenticated(true); }
        @Override public Object getPrincipal() { return identity; }
        @Override public Object getCredentials() { return ""; }
        @Override public String getName() { return identity.actor(); }
        @Override public void setAuthenticated(boolean value) {
            if (value) throw new IllegalArgumentException("Use trusted ingress");
            super.setAuthenticated(false);
        }
    }
    public record ToolCall(String action, String resourceId, String tenantHint, int amount) {}
    public record Resource(String id, String tenant) {}
    public record Request(Grant grant, ToolCall call, Resource resource) {}
    public static final class Registry {
        private final Map<String, Grant> grants = new ConcurrentHashMap<>();
        private final Set<String> revoked = ConcurrentHashMap.newKeySet();
        private final Clock clock;
        public Registry(Clock clock) { this.clock = clock; }
        // Fixture-only root seeding; never expose as an Agent tool.
        void seed(Grant grant) { grants.put(grant.id(), grant); }
        public synchronized void delegate(String parentId, Grant child) {
            Grant parent = active(parentId, new HashSet<>());
            if (!Objects.equals(child.parent(), parent.id()) || !subset(parent, child)) deny();
            if (!child.expires().isAfter(clock.instant()) || grants.putIfAbsent(child.id(), child) != null) deny();
        }
        private boolean subset(Grant p, Grant c) {
            return p.originator().equals(c.originator()) && p.task().equals(c.task())
                && p.tenant().equals(c.tenant()) && p.actions().containsAll(c.actions())
                && p.resources().containsAll(c.resources()) && !c.expires().isAfter(p.expires());
        }
        private Grant active(String id, Set<String> seen) {
            Grant g = grants.get(id);
            if (g == null || !seen.add(id) || seen.size() > 8 || revoked.contains(id) || !g.expires().isAfter(clock.instant())) deny();
            if (g.parent() != null && !subset(active(g.parent(), seen), g)) deny();
            return g;
        }
        public Grant resolve(Authentication authentication) {
            if (!(authentication instanceof DelegationAuthenticationToken token) || !authentication.isAuthenticated()) { deny(); }
            Identity i = (Identity) authentication.getPrincipal();
            Grant g = active(i.grantId(), new HashSet<>());
            if (!g.actor().equals(i.actor())) deny();
            return g;
        }
        public void revoke(String id) { revoked.add(id); }
    }
    public static final class ToolPolicy implements AuthorizationManager<Request> {
        @Override public AuthorizationResult authorize(Supplier<? extends Authentication> authentication, Request r) {
            Authentication a = authentication.get();
            boolean allowed = a instanceof DelegationAuthenticationToken && a.isAuthenticated()
                && a.getName().equals(r.grant().actor())
                && !r.call().action().startsWith("policy.")
                && r.grant().actions().contains(r.call().action())
                && r.grant().resources().contains(r.resource().id())
                && r.grant().tenant().equals(r.resource().tenant())
                && r.resource().tenant().equals(r.call().tenantHint())
                && ((r.call().action().equals("documents.read") && r.resource().id().startsWith("brief-") && r.call().amount() == 0)
                    || (r.call().action().equals("expenses.submit") && r.resource().id().startsWith("expense-")))
                && r.call().amount() >= 0 && r.call().amount() <= 500;
            return new AuthorizationDecision(allowed);
        }
    }
    public enum State { PENDING, APPROVED, REJECTED, EXPIRED, CONSUMED }
    public record Binding(String actor, String originator, String grantId, String task, String tenant, ToolCall call) {}
    private static final class Ticket {
        final Binding binding; final Instant expires; State state = State.PENDING;
        Ticket(Binding binding, Instant expires) { this.binding = binding; this.expires = expires; }
    }
    public static final class Approvals {
        private final Map<UUID, Ticket> tickets = new HashMap<>();
        private final Clock clock;
        public Approvals(Clock clock) { this.clock = clock; }
        public synchronized UUID open(Binding binding) {
            UUID id = UUID.randomUUID(); tickets.put(id, new Ticket(binding, clock.instant().plusSeconds(300))); return id;
        }
        public synchronized void decide(UUID id, Authentication approver, boolean approve) {
            Ticket t = ticket(id);
            boolean human = approver != null && approver.isAuthenticated()
                && !(approver instanceof DelegationAuthenticationToken)
                && approver.getAuthorities().stream().anyMatch(a -> a.getAuthority().equals("ROLE_APPROVER"))
                && !approver.getName().equals(t.binding.originator());
            if (!human || t.state != State.PENDING) deny();
            t.state = approve ? State.APPROVED : State.REJECTED;
        }
        private Ticket ticket(UUID id) {
            Ticket t = tickets.get(id); if (t == null) { deny(); }
            if (!t.expires.isAfter(clock.instant())) { t.state = State.EXPIRED; deny(); }
            return t;
        }
        public synchronized void consume(UUID id, Binding binding) {
            Ticket t = ticket(id);
            if (t.state != State.APPROVED || !t.binding.equals(binding)) deny();
            t.state = State.CONSUMED;
        }
    }
    public record Outcome(String status, UUID ticket) {}
    public static final class Gateway {
        private final Registry registry; private final Approvals approvals;
        private final ToolPolicy policy = new ToolPolicy();
        private final Map<String, Resource> resources = Map.of("brief-a", new Resource("brief-a", "acme"),
            "expense-a", new Resource("expense-a", "acme"), "brief-b", new Resource("brief-b", "other"));
        private final AtomicInteger effects = new AtomicInteger();
        public Gateway(Registry registry, Approvals approvals) { this.registry = registry; this.approvals = approvals; }
        public int effects() { return effects.get(); }
        // Sole entry, used by HTTP adapters and direct/asynchronous calls alike.
        public synchronized Outcome execute(ToolCall call, UUID approvalId) {
            Authentication a = SecurityContextHolder.getContext().getAuthentication();
            Grant grant = registry.resolve(a);                         // ① trusted registry, full parent chain
            Resource resource = resources.get(call.resourceId());     // ② server-owned tenant metadata
            if (resource == null) { deny(); }
            Request request = new Request(grant, call, resource);
            AuthorizationResult decision = policy.authorize(() -> a, request);
            if (decision == null || !decision.isGranted()) deny();     // ③ explicit fail-closed; verify(null) abstains
            Binding binding = new Binding(grant.actor(), grant.originator(), grant.id(), grant.task(), resource.tenant(), call);
            if (approvalId != null) {
                approvals.consume(approvalId, binding);               // ④ every approval-based resume must match
            }
            else if (call.action().equals("expenses.submit") && call.amount() > 100) {
                return new Outcome("PENDING", approvals.open(binding));
            }
            // No arbitrary reflection or callback supplied by model; dispatch is a fixed allowlist.
            if (call.action().equals("expenses.submit")) effects.incrementAndGet();
            return new Outcome("EXECUTED", null);
        }
    }
    static void deny() { throw new AccessDeniedException("TOOL_NOT_ALLOWED"); }
}
