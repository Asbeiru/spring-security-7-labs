package com.zhouzhou.agent.rag;

import java.util.List;

import org.springframework.ai.document.Document;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.stereotype.Component;

@Component
public class DocumentAclFilter {

    // 出参二次清洗：确保最终装配进 LLM 上下文的文档片段，每一篇都合法合规
    @PostFilter("hasPermission(filterObject, 'READ') or filterObject.metadata['owner'] == authentication.name")
    public List<Document> filter(List<Document> retrievedDocs) {
        return retrievedDocs; // 框架会剔除不满足表达式的元素
    }
}
