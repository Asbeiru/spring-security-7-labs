package com.zhouzhou.agent.security;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

public record TrustedIdentity(String issuer, String tenant, String subject, String clientId) {
    public static TrustedIdentity current() {
        return from(SecurityContextHolder.getContext().getAuthentication());
    }

    public static TrustedIdentity from(Authentication authentication) {
        Jwt jwt = token(authentication);
        return new TrustedIdentity(required(jwt, "iss"), required(jwt, "tenant_id"),
                required(jwt, "sub"), required(jwt, "client_id"));
    }

    public static Jwt token(Authentication authentication) {
        if (!(authentication instanceof JwtAuthenticationToken token) || !token.isAuthenticated()) {
            throw new AccessDeniedException("需要已验证的 JWT 身份");
        }
        return token.getToken();
    }

    public static int clearance(Authentication authentication) {
        Object value = token(authentication).getClaims().get("security_clearance");
        if (value instanceof Number number) {
            double level = number.doubleValue();
            if (Double.isFinite(level) && level >= 0 && level <= 5 && level == Math.rint(level)) {
                return (int) level;
            }
        }
        throw new AccessDeniedException("无效的 security_clearance");
    }

    private static String required(Jwt jwt, String claim) {
        Object value = jwt.getClaims().get(claim);
        if (!(value instanceof String text) || text.isBlank()) {
            throw new AccessDeniedException("令牌缺少 " + claim);
        }
        return text;
    }
}
