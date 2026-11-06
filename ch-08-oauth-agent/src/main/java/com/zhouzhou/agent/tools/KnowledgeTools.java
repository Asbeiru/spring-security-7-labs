package com.zhouzhou.agent.tools;

import java.util.List;
import org.springframework.ai.tool.annotation.Tool;
import org.springframework.ai.tool.annotation.ToolParam;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import com.zhouzhou.agent.rag.EnterpriseRagService;

@Service
public class KnowledgeTools {
    private final EnterpriseRagService ragService;

    public KnowledgeTools(EnterpriseRagService ragService) {
        this.ragService = ragService;
    }

    @Tool(description = "查询当前用户有权阅读的企业文档")
    @PreAuthorize("hasAuthority('SCOPE_mcp:rag:query')")
    public List<String> searchKnowledge(@ToolParam(description = "检索问题") String query) {
        return this.ragService.retrieveRelevantDocs(query).stream().map(document -> document.getText()).toList();
    }
}
