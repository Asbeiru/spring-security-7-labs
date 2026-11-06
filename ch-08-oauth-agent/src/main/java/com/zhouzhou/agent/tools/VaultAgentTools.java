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
import com.zhouzhou.agent.security.AccountAccess;
import com.zhouzhou.agent.security.TrustedIdentity;

@Service
public class VaultAgentTools {
    private static final Logger log = LoggerFactory.getLogger(VaultAgentTools.class);
    private final AccountAccess accountAccess;

    public VaultAgentTools(AccountAccess accountAccess) {
        this.accountAccess = accountAccess;
    }

    public record TransferExecutionResult(String txId, String status, String message) { }

    @Tool(description = "分析指定账户的合规风险")
    @PreAuthorize("hasAuthority('SCOPE_mcp:analytics:read') and @accountAccess.owns(authentication, #accountId)")
    public String analyzeAccountRisk(@ToolParam(description = "账户 ID") String accountId) {
        return "演示账户 " + accountId + "：未查询真实财务数据。";
    }

    @Tool(description = "从当前租户金库向本租户账户模拟调拨，需要人工审批")
    @PreAuthorize("hasAuthority('SCOPE_mcp:vault:transfer') and hasRole('FINANCE_ADMIN') "
            + "and @accountAccess.canTransfer(authentication, #targetAccount, #amount)")
    @RequiresHumanApproval
    public TransferExecutionResult transferVaultFunds(
            @ToolParam(description = "目标账户") String targetAccount,
            @ToolParam(description = "划转金额（元）") BigDecimal amount) {
        String source = this.accountAccess.treasury(TrustedIdentity.current());
        String txId = "TX-" + UUID.randomUUID();
        log.info("模拟调拨：来源 {}，目标 {}，金额 {}，编号 {}", source, targetAccount, amount, txId);
        return new TransferExecutionResult(txId, "SIMULATED", "授权通过，未发生真实资金变动");
    }
}
