package com.zhouzhou.agent.rag;

import java.util.List;
import java.util.Map;

import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;

@Service
public class EnterpriseRagService {

    private final VectorStore vectorStore;

    public EnterpriseRagService(VectorStore vectorStore) {
        this.vectorStore = vectorStore;
    }

    public List<Document> retrieveRelevantDocs(String userQuery) {
        // 1. 从当前线程的安全上下文中提取已验签的 JWT
        Jwt jwt = currentJwt();
        String currentTenant = jwt.getClaimAsString("tenant_id");
        Number clearance = jwt.getClaim("security_clearance");
        if (currentTenant == null || clearance == null) {
            throw new AccessDeniedException("令牌缺少租户或密级声明");
        }

        // 2. 构造 Pre-Filtering 过滤表达式：租户隔离 + 密级不越界
        FilterExpressionBuilder b = new FilterExpressionBuilder();
        Filter.Expression filter = b.and(
                b.eq("tenant_id", currentTenant),
                b.lte("confidentiality_level", clearance.intValue())).build();

        // 3. 携带过滤表达式执行向量检索：不满足条件的切片不会进入候选集
        SearchRequest searchRequest = SearchRequest.builder()
                .query(userQuery)
                .topK(5)
                .filterExpression(filter)
                .build();

        return this.vectorStore.similaritySearch(searchRequest);
    }

    public void ingest(String content, int confidentialityLevel) {
        Jwt jwt = currentJwt();
        Document document = new Document(content, Map.of(
                "tenant_id", jwt.getClaimAsString("tenant_id"),
                "owner", jwt.getSubject(),
                "confidentiality_level", confidentialityLevel));
        this.vectorStore.add(List.of(document));
    }

    private static Jwt currentJwt() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (!(authentication instanceof JwtAuthenticationToken jwtAuthentication)) {
            throw new AccessDeniedException("需要 JWT 认证");
        }
        return jwtAuthentication.getToken();
    }
}
