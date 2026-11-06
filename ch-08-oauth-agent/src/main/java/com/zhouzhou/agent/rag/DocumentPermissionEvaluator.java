package com.zhouzhou.agent.rag;

import java.io.Serializable;

import org.springframework.ai.document.Document;
import org.springframework.security.access.PermissionEvaluator;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

@Component
public class DocumentPermissionEvaluator implements PermissionEvaluator {

    private final DocumentAclService aclService;

    public DocumentPermissionEvaluator(DocumentAclService aclService) {
        this.aclService = aclService;
    }

    @Override
    public boolean hasPermission(Authentication authentication, Object target, Object permission) {
        return target instanceof Document document
                && this.aclService.isGranted(authentication.getName(),
                        (String) document.getMetadata().get("doc_id"), String.valueOf(permission));
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
                                 Object permission) {
        return false;
    }
}
