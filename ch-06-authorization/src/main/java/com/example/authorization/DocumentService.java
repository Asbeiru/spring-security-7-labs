package com.example.authorization;

import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

@Service
class DocumentService {

    private final Map<String, Document> documents = Map.of(
            "d1", new Document("d1", "t1", "alice", "Alice 的合同"),
            "d2", new Document("d2", "t1", "bob", "Bob 的报价"),
            "d3", new Document("d3", "t2", "carol", "Carol 的计划"),
            "d4", new Document("d4", "t2", "alice", "Alice 的跨租户草稿"));

    @PreAuthorize("hasAuthority('TENANT_' + #tenantId)")
    @PostAuthorize("returnObject.tenantId() == #tenantId and returnObject.owner() == authentication.name")
    public Document read(String tenantId, String documentId) {
        Document document = this.documents.get(documentId);
        if (document == null) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND);
        }
        return document;
    }

    @PreAuthorize("hasRole('ADMIN')")
    public Map<String, Integer> adminSummary() {
        return Map.of("documents", this.documents.size());
    }

    record Document(String id, String tenantId, String owner, String title) {
    }
}
