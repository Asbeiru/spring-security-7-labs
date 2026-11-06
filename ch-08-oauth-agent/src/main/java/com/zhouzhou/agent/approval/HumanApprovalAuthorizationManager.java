package com.zhouzhou.agent.approval;

import java.util.Arrays;
import java.util.function.Supplier;
import org.aopalliance.intercept.MethodInvocation;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import com.zhouzhou.agent.security.TrustedIdentity;

public final class HumanApprovalAuthorizationManager implements AuthorizationManager<MethodInvocation> {
    private final ObjectProvider<ApprovalService> approvalService;

    public HumanApprovalAuthorizationManager(ObjectProvider<ApprovalService> approvalService) {
        this.approvalService = approvalService;
    }

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            MethodInvocation invocation) {
        TrustedIdentity requester = TrustedIdentity.from(authentication.get());
        String operation = ApprovalService.operationOf(invocation.getMethod());
        String argsHash = ApprovalService.argsHash(invocation.getMethod(), invocation.getArguments());
        ApprovalService.Binding binding = new ApprovalService.Binding(requester, operation, argsHash);
        this.approvalService.getObject().requireApproval(binding, Arrays.toString(invocation.getArguments()))
                .ifPresent(ticket -> { throw new HumanApprovalRequiredException(ticket.id()); });
        return new AuthorizationDecision(true);
    }
}
