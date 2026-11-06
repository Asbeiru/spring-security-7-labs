package com.zhouzhou.agent.approval;

import java.lang.reflect.Method;
import java.math.BigDecimal;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import org.springframework.stereotype.Service;

/**
 * 人工审批工单服务（内存实现，生产环境请替换为数据库 + 审批系统回调）
 */
@Service
public class ApprovalService {

    public enum Status { PENDING, APPROVED }

    public record ApprovalTicket(String id, String requester, String operation, String argsHash,
                                 String argsSummary, Instant expiresAt, Status status, String approver) {

        boolean isExpired() {
            return Instant.now().isAfter(this.expiresAt);
        }

        ApprovalTicket approvedBy(String approver) {
            return new ApprovalTicket(this.id, this.requester, this.operation, this.argsHash,
                    this.argsSummary, this.expiresAt, Status.APPROVED, approver);
        }
    }

    private static final Duration TICKET_TTL = Duration.ofMinutes(15);

    /** key = 发起人 + 操作 + 参数哈希，同一个具体动作同时只存在一张有效工单 */
    private final Map<String, ApprovalTicket> ticketsByBinding = new ConcurrentHashMap<>();

    /** ticketId -> bindingKey */
    private final Map<String, String> bindingByTicketId = new ConcurrentHashMap<>();

    /**
     * 查找或创建待审批工单
     */
    public ApprovalTicket findOrCreatePending(String requester, String operation, String argsHash, String argsSummary) {
        String bindingKey = bindingKey(requester, operation, argsHash);
        ApprovalTicket ticket = this.ticketsByBinding.compute(bindingKey, (key, existing) -> {
            if (existing != null && !existing.isExpired()) {
                return existing;
            }
            return new ApprovalTicket("TICKET-" + UUID.randomUUID().toString().substring(0, 8), requester,
                    operation, argsHash, argsSummary, Instant.now().plus(TICKET_TTL), Status.PENDING, null);
        });
        this.bindingByTicketId.put(ticket.id(), bindingKey);
        // 真实生产中：在此向审批人推送企业微信 / 钉钉 / App 通知
        return ticket;
    }

    /**
     * 人工审批：只能审批待审批、未过期的工单，且审批人不能是发起人本人
     */
    public ApprovalTicket approve(String ticketId, String approver) {
        String bindingKey = this.bindingByTicketId.get(ticketId);
        if (bindingKey == null) {
            throw new IllegalArgumentException("工单不存在: " + ticketId);
        }
        ApprovalTicket approved = this.ticketsByBinding.computeIfPresent(bindingKey, (key, ticket) -> {
            if (!ticket.id().equals(ticketId) || ticket.status() != Status.PENDING || ticket.isExpired()) {
                throw new IllegalStateException("工单状态不允许审批: " + ticketId);
            }
            if (ticket.requester().equals(approver)) {
                throw new IllegalStateException("审批人不能是发起人本人");
            }
            return ticket.approvedBy(approver);
        });
        if (approved == null) {
            throw new IllegalStateException("工单已失效: " + ticketId);
        }
        return approved;
    }

    /**
     * 原子地消费一张与（发起人, 操作, 参数）完全匹配的已批准工单；消费后立即作废
     */
    public boolean tryConsume(String requester, String operation, String argsHash) {
        AtomicBoolean consumed = new AtomicBoolean(false);
        this.ticketsByBinding.computeIfPresent(bindingKey(requester, operation, argsHash), (key, ticket) -> {
            if (ticket.status() == Status.APPROVED && !ticket.isExpired()) {
                consumed.set(true);
                this.bindingByTicketId.remove(ticket.id());
                return null; // 返回 null 即从 Map 中移除，保证一次性
            }
            return ticket;
        });
        return consumed.get();
    }

    public long pendingCount() {
        return this.ticketsByBinding.values().stream().filter(t -> t.status() == Status.PENDING).count();
    }

    /**
     * 测试隔离用。工单存在单例里，上一个用例留下的待审批单会让 pendingCount 失真。
     */
    public void clear() {
        this.ticketsByBinding.clear();
        this.bindingByTicketId.clear();
    }

    public static String operationOf(Method method) {
        return method.getDeclaringClass().getName() + "#" + method.getName();
    }

    /**
     * 参数哈希：BigDecimal 归一化（100 与 100.00 视为相同金额），并以“长度:值”拼接防止分隔符歧义
     */
    public static String argsHash(Method method, Object[] args) {
        StringBuilder canonical = new StringBuilder(operationOf(method));
        for (Object arg : args) {
            String value = (arg instanceof BigDecimal decimal)
                    ? decimal.stripTrailingZeros().toPlainString()
                    : String.valueOf(arg);
            canonical.append('|').append(value.length()).append(':').append(value);
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(canonical.toString().getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        }
        catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException(ex);
        }
    }

    private static String bindingKey(String requester, String operation, String argsHash) {
        return requester + "|" + operation + "|" + argsHash;
    }
}
