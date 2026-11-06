package com.example.authorization;

import java.util.function.Supplier;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.intercept.RequestAuthorizationContext;
import org.springframework.stereotype.Component;

@Component
final class TenantAuthorizationManager implements AuthorizationManager<RequestAuthorizationContext> {

    @Override
    public AuthorizationResult authorize(Supplier<? extends Authentication> authentication,
            RequestAuthorizationContext context) {
        String tenantId = context.getVariables().get("tenantId");
        if (tenantId == null) {
            return new AuthorizationDecision(false);
        }
        Authentication current = authentication.get();
        boolean granted = current.getAuthorities().stream()
                .anyMatch(authority -> ("TENANT_" + tenantId).equals(authority.getAuthority()));
        return new AuthorizationDecision(granted);
    }
}
