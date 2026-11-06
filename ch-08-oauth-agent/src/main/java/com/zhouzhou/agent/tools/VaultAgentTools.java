package com.zhouzhou.agent.tools;

import java.math.BigDecimal;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import com.zhouzhou.agent.approval.RequiresHumanApproval;

/**
 * AI 智能体可调用的核心资产工具服务
 */
@Service
public class VaultAgentTools {

    private static final Logger log = LoggerFactory.getLogger(VaultAgentTools.class);

    /**
     * 资产调拨结果
     */
    public record TransferExecutionResult(String txId, String status, String message) {
    }

    /**
     * 工具 1：低风险账户分析
     */
    @Tool(description = "分析指定账户的合规风险")
    @PreAuthorize("hasAuthority('SCOPE_mcp:analytics:read')")
    public String analyzeAccountRisk(@ToolParam(description = "账户 ID") String accountId) {
        log.info("执行低风险工具：分析账户 {} 的合规状态", accountId);
        return "账户 " + accountId + " 财务评级良好，无违规记录。";
    }

    /**
     * 工具 2：高危资金调拨
     *
     * 门禁 1：@PreAuthorize 校验令牌中必须同时含有指定 Scope 与角色
     * 门禁 2：@RequiresHumanApproval 要求存在一张与本次参数完全匹配的已批准工单
     */
    @Tool(description = "从金库向目标账户划转资金。高风险操作，需要人工审批")
    @PreAuthorize("hasAuthority('SCOPE_mcp:vault:transfer') and hasRole('FINANCE_ADMIN')")
    @RequiresHumanApproval
    public TransferExecutionResult transferVaultFunds(
            @ToolParam(description = "目标账户") String targetAccount,
            @ToolParam(description = "划转金额（元）") BigDecimal amount) {
        // 能走到这里，说明两道门禁均已通过
        String txId = "TX-" + UUID.randomUUID();
        log.info("资金调拨成功，目标账户: {}，金额: {}，交易流水号: {}", targetAccount, amount, txId);
        return new TransferExecutionResult(txId, "SUCCESS", "调拨执行成功");
    }
}
