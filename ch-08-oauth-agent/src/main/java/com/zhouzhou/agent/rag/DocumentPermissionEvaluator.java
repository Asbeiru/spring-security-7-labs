package com.zhouzhou.agent.rag;

import java.io.Serializable;
import java.util.Map;
import com.zhouzhou.agent.security.TrustedIdentity;
import org.springframework.ai.document.Document;
import org.springframework.security.access.AccessDeniedException;
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
        if (!(target instanceof Document document) || !"READ".equals(permission)) {
            return false;
        }
        try {
            TrustedIdentity identity = TrustedIdentity.from(authentication);
            int clearance = TrustedIdentity.clearance(authentication);
            Map<String, Object> metadata = document.getMetadata();
            Object level = metadata.get("confidentiality_level");
            if (!identity.issuer().equals(metadata.get("issuer"))
                    || !identity.tenant().equals(metadata.get("tenant_id"))
                    || !(level instanceof Number number)
                    || !Double.isFinite(number.doubleValue())
                    || number.doubleValue() != Math.rint(number.doubleValue())
                    || number.doubleValue() < 0 || number.doubleValue() > clearance) {
                return false;
            }
            return identity.subject().equals(metadata.get("owner"))
                    || this.aclService.isGranted(identity, document.getId(), "READ");
        }
        catch (AccessDeniedException ex) {
            return false;
        }
    }

    @Override
    public boolean hasPermission(Authentication authentication, Serializable targetId, String targetType,
            Object permission) {
        return false;
    }
}
