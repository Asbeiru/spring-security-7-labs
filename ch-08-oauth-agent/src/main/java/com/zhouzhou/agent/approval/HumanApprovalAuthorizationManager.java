package com.zhouzhou.agent.approval;

import java.util.Arrays;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;

/**
 * 参数绑定的人工审批授权管理器
 */
public final class HumanApprovalAuthorizationManager implements AuthorizationManager<MethodInvocation> {

    private final ApprovalService approvalService;

    public HumanApprovalAuthorizationManager(ApprovalService approvalService) {
        this.approvalService = approvalService;
    }

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
                                         MethodInvocation invocation) {
        Authentication auth = authentication.get();
        if (auth == null || !auth.isAuthenticated()) {
            return new AuthorizationDecision(false);
        }

        String requester = auth.getName();
        String operation = ApprovalService.operationOf(invocation.getMethod());
        String argsHash = ApprovalService.argsHash(invocation.getMethod(), invocation.getArguments());

        if (this.approvalService.tryConsume(requester, operation, argsHash)) {
            return new AuthorizationDecision(true);
        }

        ApprovalService.ApprovalTicket ticket = this.approvalService.findOrCreatePending(
                requester, operation, argsHash, Arrays.toString(invocation.getArguments()));
        throw new HumanApprovalRequiredException(ticket.id());
    }
}
