package com.zhouzhou.agent.approval;

/**
 * 调用已被挂起、等待人工审批。异常信息会作为工具结果回传给模型，由 Agent 转告用户。
 */
public class HumanApprovalRequiredException extends RuntimeException {

    private final String ticketId;

    public HumanApprovalRequiredException(String ticketId) {
        super("该操作属于高危动作，已提交人工审批工单 " + ticketId
                + "。请等待审批通过后，使用完全相同的参数重新发起。");
        this.ticketId = ticketId;
    }

    public String getTicketId() {
        return this.ticketId;
    }
}
