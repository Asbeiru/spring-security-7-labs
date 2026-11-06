package com.zhouzhou.agent.rag;

import java.util.List;
import java.util.Map;
import org.springframework.ai.document.Document;
import org.springframework.ai.vectorstore.SearchRequest;
import org.springframework.ai.vectorstore.VectorStore;
import org.springframework.ai.vectorstore.filter.Filter;
import org.springframework.ai.vectorstore.filter.FilterExpressionBuilder;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import com.zhouzhou.agent.security.TrustedIdentity;

@Service
public class EnterpriseRagService {
    private final VectorStore vectorStore;
    private final DocumentAclFilter aclFilter;

    public EnterpriseRagService(VectorStore vectorStore, DocumentAclFilter aclFilter) {
        this.vectorStore = vectorStore;
        this.aclFilter = aclFilter;
    }

    @PreAuthorize("hasAuthority('SCOPE_mcp:rag:query')")
    public List<Document> retrieveRelevantDocs(String userQuery) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        TrustedIdentity identity = TrustedIdentity.from(authentication);
        int clearance = TrustedIdentity.clearance(authentication);
        FilterExpressionBuilder b = new FilterExpressionBuilder();
        Filter.Expression filter = b.and(
                b.and(b.eq("issuer", identity.issuer()), b.eq("tenant_id", identity.tenant())),
                b.lte("confidentiality_level", clearance)).build();
        SearchRequest request = SearchRequest.builder()
                .query(userQuery).topK(5).filterExpression(filter).build();
        return this.aclFilter.filter(this.vectorStore.similaritySearch(request));
    }

    @PreAuthorize("hasAuthority('SCOPE_rag:ingest')")
    public void ingest(String content, int confidentialityLevel) {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        TrustedIdentity identity = TrustedIdentity.from(authentication);
        int clearance = TrustedIdentity.clearance(authentication);
        if (confidentialityLevel < 0 || confidentialityLevel > clearance) {
            throw new AccessDeniedException("不能写入超出本人密级的文档");
        }
        Document document = new Document(content, Map.of(
                "issuer", identity.issuer(),
                "tenant_id", identity.tenant(),
                "owner", identity.subject(),
                "confidentiality_level", confidentialityLevel));
        this.vectorStore.add(List.of(document));
    }
}
