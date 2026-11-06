package com.zhouzhou.agent.approval;

import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.HashMap;
import java.util.HexFormat;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import com.zhouzhou.agent.security.TrustedIdentity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

/** 单进程内存审批示例；不持久化，也不承担转账事务。 */
@Service
public class ApprovalService {
    public enum Status { PENDING, APPROVED }
    public record Binding(TrustedIdentity requester, String operation, String argsHash) { }
    public record ApprovalTicket(String id, Binding binding, String argsSummary,
            Instant expiresAt, Status status, TrustedIdentity approver) { }

    private static final Duration TICKET_TTL = Duration.ofMinutes(15);
    private final Map<Binding, ApprovalTicket> tickets = new HashMap<>();
    private final Clock clock;

    public ApprovalService() {
        this(Clock.systemUTC());
    }

    public ApprovalService(Clock clock) {
        this.clock = clock;
    }

    // 空结果表示已消费批准；有结果表示本次调用必须停在方法体之前。
    public synchronized Optional<ApprovalTicket> requireApproval(Binding binding, String summary) {
        this.tickets.values().removeIf(ticket -> !this.clock.instant().isBefore(ticket.expiresAt()));
        ApprovalTicket ticket = this.tickets.get(binding);
        if (ticket != null && ticket.status() == Status.APPROVED) {
            this.tickets.remove(binding);
            return Optional.empty();
        }
        if (ticket == null) {
            ticket = new ApprovalTicket("TICKET-" + UUID.randomUUID(), binding, summary,
                    this.clock.instant().plus(TICKET_TTL), Status.PENDING, null);
            this.tickets.put(binding, ticket);
        }
        return Optional.of(ticket);
    }

    @PreAuthorize("hasRole('RISK_APPROVER')")
    public synchronized ApprovalTicket approve(String ticketId) {
        TrustedIdentity approver = TrustedIdentity.current();
        ApprovalTicket ticket = this.tickets.values().stream()
                .filter(candidate -> candidate.id().equals(ticketId)).findFirst()
                .orElseThrow(() -> new AccessDeniedException("工单不存在或不可审批"));
        TrustedIdentity requester = ticket.binding().requester();
        if (!requester.issuer().equals(approver.issuer()) || !requester.tenant().equals(approver.tenant())
                || requester.subject().equals(approver.subject())) {
            throw new AccessDeniedException("需要同租户的另一位审批人");
        }
        if (ticket.status() != Status.PENDING || !this.clock.instant().isBefore(ticket.expiresAt())) {
            throw new AccessDeniedException("工单已过期或状态不允许审批");
        }
        ApprovalTicket approved = new ApprovalTicket(ticket.id(), ticket.binding(), ticket.argsSummary(),
                ticket.expiresAt(), Status.APPROVED, approver);
        this.tickets.put(ticket.binding(), approved);
        return approved;
    }

    public synchronized long pendingCount() {
        return this.tickets.values().stream().filter(t -> t.status() == Status.PENDING).count();
    }

    public synchronized void clear() {
        this.tickets.clear();
    }

    public static String operationOf(Method method) {
        return method.toGenericString();
    }

    // 本例仅接收 String 与 BigDecimal；新增类型时需定义稳定的参数规范化方式。
    public static String argsHash(Method method, Object[] args) {
        StringBuilder canonical = new StringBuilder(operationOf(method));
        for (Object arg : args) {
            String value;
            if (arg instanceof BigDecimal decimal) {
                value = "decimal:" + decimal.stripTrailingZeros().toPlainString();
            }
            else if (arg instanceof String text) {
                value = "string:" + text;
            }
            else {
                throw new IllegalArgumentException("审批参数只支持字符串与金额");
            }
            canonical.append('|').append(value.length()).append(':').append(value);
        }
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256")
                    .digest(canonical.toString().getBytes(StandardCharsets.UTF_8)));
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }
}
