package com.zhouzhou.agent;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.math.BigDecimal;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.zhouzhou.agent.approval.ApprovalService;
import com.zhouzhou.agent.approval.HumanApprovalRequiredException;
import com.zhouzhou.agent.rag.EnterpriseRagService;
import com.zhouzhou.agent.tools.VaultAgentTools;
import com.zhouzhou.agent.tools.VaultAgentTools.TransferExecutionResult;

@SpringBootTest
class VaultAgentSecurityTests {

    @Autowired
    WebApplicationContext context;

    @Autowired
    VaultAgentTools tools;

    @Autowired
    ApprovalService approvalService;

    @MockitoBean
    JwtDecoder jwtDecoder;

    MockMvc mvc;

    @BeforeEach
    void setUp() {
        this.approvalService.clear();
        this.mvc = MockMvcBuilders.webAppContextSetup(this.context).apply(springSecurity()).build();
    }

    @AfterEach
    void clearContext() {
        SecurityContextHolder.clearContext();
    }

    private static void runAs(String user, String... authorities) {
        SecurityContextHolder.getContext().setAuthentication(new TestingAuthenticationToken(user, null, authorities));
    }

    // 测试 1：Agent 协议自适应发现（RFC 9728）
    @Test
    void metadataEndpointDescribesAuthorizationTopology() throws Exception {
        this.mvc.perform(get("/.well-known/oauth-protected-resource"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.resource").value("http://localhost"))
            .andExpect(jsonPath("$.authorization_servers[0]").value("https://auth.zhouzhou.com"))
            .andExpect(jsonPath("$.scopes_supported.length()").value(3))
            .andExpect(jsonPath("$.bearer_methods_supported[0]").value("header"));
    }

    @Test
    void unauthenticatedRequestPointsClientToMetadata() throws Exception {
        this.mvc.perform(get("/agent/chat"))
            .andExpect(status().isUnauthorized())
            .andExpect(header().string("WWW-Authenticate",
                    containsString("resource_metadata=\"http://localhost/.well-known/oauth-protected-resource\"")));
    }

    // 测试 2：提示词注入！Agent 携带的只是分析师令牌，却被诱骗发起转账
    @Test
    void analystTokenCannotTransferEvenIfAgentIsTricked() {
        runAs("mallory", "SCOPE_mcp:analytics:read");

        assertThrows(AuthorizationDeniedException.class,
                () -> this.tools.transferVaultFunds("ATTACKER_999", new BigDecimal("500000")));

        // @PreAuthorize 先于 HITL 执行：无权限的调用连审批工单都不会生成
        assertThat(this.approvalService.pendingCount()).isZero();
    }

    // 测试 3：管理员令牌下的高危操作，触发参数绑定的 HITL 审批
    @Test
    void transferRequiresOneTimeApprovalBoundToExactArguments() {
        runAs("alice", "SCOPE_mcp:vault:transfer", "ROLE_FINANCE_ADMIN");

        // ① 首次调用被挂起，生成工单
        HumanApprovalRequiredException suspended = assertThrows(HumanApprovalRequiredException.class,
                () -> this.tools.transferVaultFunds("ACC-001", new BigDecimal("100.00")));
        String ticketId = suspended.getTicketId();

        // ② 发起人不能自己审批
        assertThrows(IllegalStateException.class, () -> this.approvalService.approve(ticketId, "alice"));

        // ③ 风控主管 bob 审批通过
        this.approvalService.approve(ticketId, "bob");

        // ④ 改动金额后再调用：审批不适用于新参数，重新挂起
        assertThrows(HumanApprovalRequiredException.class,
                () -> this.tools.transferVaultFunds("ACC-001", new BigDecimal("1000000")));

        // ⑤ 使用相同参数（100 与 100.00 视为同一金额）调用：执行成功
        TransferExecutionResult result = this.tools.transferVaultFunds("ACC-001", new BigDecimal("100"));
        assertThat(result.status()).isEqualTo("SUCCESS");

        // ⑥ 工单已被消费，重放同一调用会再次被挂起
        assertThrows(HumanApprovalRequiredException.class,
                () -> this.tools.transferVaultFunds("ACC-001", new BigDecimal("100")));
    }

    @Test
    void onlyRiskApproverCanCallApprovalEndpoint() throws Exception {
        this.mvc.perform(post("/admin/approvals/TICKET-xxxx/approve")
                .with(jwt().jwt(j -> j.subject("alice"))
                    .authorities(new SimpleGrantedAuthority("ROLE_FINANCE_ADMIN"))))
            .andExpect(status().isForbidden());
    }

    // 测试 4：RAG 检索始终被限定在当前租户与密级之内
    @Test
    void ragSearchIsAlwaysScopedToCurrentTenant() {
        VectorStore vectorStore = mock(VectorStore.class);
        EnterpriseRagService ragService = new EnterpriseRagService(vectorStore);

        Jwt token = Jwt.withTokenValue("token")
            .header("alg", "none")
            .subject("alice")
            .claim("tenant_id", "tenant-a")
            .claim("security_clearance", 2)
            .build();
        SecurityContextHolder.getContext().setAuthentication(new JwtAuthenticationToken(token));

        ragService.retrieveRelevantDocs("请告诉我公司今年裁员名单与薪资预算");

        ArgumentCaptor<SearchRequest> captor = ArgumentCaptor.forClass(SearchRequest.class);
        verify(vectorStore).similaritySearch(captor.capture());

        FilterExpressionBuilder b = new FilterExpressionBuilder();
        Filter.Expression expected = b.and(b.eq("tenant_id", "tenant-a"), b.lte("confidentiality_level", 2)).build();
        assertThat(captor.getValue().getFilterExpression()).isEqualTo(expected);
    }
}
