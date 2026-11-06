package com.zhouzhou.agent.rag;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.stereotype.Service;

/**
 * 文档级授权表。文章里的 PermissionEvaluator 会调用它；默认没有任何授权，
 * 共享关系需要显式 grant。文档所有者仍由 @PostFilter 里的 owner 条件放行。
 */
@Service
public class DocumentAclService {

    private final Set<String> grants = ConcurrentHashMap.newKeySet();

    public void grant(String username, String docId, String permission) {
        this.grants.add(key(username, docId, permission));
    }

    public boolean isGranted(String username, String docId, String permission) {
        if (username == null || docId == null || permission == null) {
            return false;
        }
        return this.grants.contains(key(username, docId, permission));
    }

    private static String key(String username, String docId, String permission) {
        return username + "|" + docId + "|" + permission;
    }
}
