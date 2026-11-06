package com.zhouzhou.agent.rag;

import java.util.ArrayList;
import java.util.List;
import org.springframework.ai.document.Document;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.stereotype.Component;

@Component
public class DocumentAclFilter {
    @PostFilter("hasPermission(filterObject, 'READ')")
    public List<Document> filter(List<Document> retrievedDocs) {
        return new ArrayList<>(retrievedDocs);
    }
}
