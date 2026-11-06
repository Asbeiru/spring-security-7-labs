package com.example.authorization;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
class DocumentController {

    private final DocumentService documents;

    DocumentController(DocumentService documents) {
        this.documents = documents;
    }

    @GetMapping("/api/tenants/{tenantId}/documents/{documentId}")
    DocumentService.Document read(@PathVariable String tenantId, @PathVariable String documentId) {
        return this.documents.read(tenantId, documentId);
    }

    @GetMapping("/api/admin/summary")
    Map<String, Integer> summary() {
        return this.documents.adminSummary();
    }
}
