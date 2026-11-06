package com.zhouzhou.agent.rag;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import com.zhouzhou.agent.security.TrustedIdentity;
import org.springframework.stereotype.Service;

/** 示例 ACL 目录，由可信管理流程维护，不向模型暴露授权写接口。 */
@Service
public class DocumentAclService {
    private record Grant(String issuer, String tenant, String subject, String documentId, String permission) { }
    private final Set<Grant> grants = ConcurrentHashMap.newKeySet();

    public void grant(TrustedIdentity identity, String documentId, String permission) {
        this.grants.add(new Grant(identity.issuer(), identity.tenant(), identity.subject(), documentId, permission));
    }

    public boolean isGranted(TrustedIdentity identity, String documentId, String permission) {
        return this.grants.contains(new Grant(identity.issuer(), identity.tenant(), identity.subject(), documentId, permission));
    }

    public void clear() {
        this.grants.clear();
    }
}
