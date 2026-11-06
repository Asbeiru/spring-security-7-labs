package com.zhouzhou.agent.approval;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/admin/approvals")
public class ApprovalController {

    private final ApprovalService approvalService;

    public ApprovalController(ApprovalService approvalService) {
        this.approvalService = approvalService;
    }

    @PostMapping("/{ticketId}/approve")
    @PreAuthorize("hasRole('RISK_APPROVER')")
    public ApprovalService.ApprovalTicket approve(@PathVariable String ticketId, Authentication approver) {
        return this.approvalService.approve(ticketId, approver.getName());
    }
}
