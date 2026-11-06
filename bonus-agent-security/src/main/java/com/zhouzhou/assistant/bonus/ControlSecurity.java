package com.zhouzhou.assistant.bonus;

import org.springframework.context.annotation.*;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import static com.zhouzhou.assistant.bonus.AgentSecurity.*;

@Configuration
public class ControlSecurity {
    @Bean @Order(1)
    SecurityFilterChain control(HttpSecurity http) throws Exception {
        return http.securityMatcher("/control/**").authorizeHttpRequests(a -> a.anyRequest().access((authentication, context) -> {
            var caller = authentication.get();
            boolean allowed = caller != null && caller.isAuthenticated()
                && !(caller instanceof DelegationAuthenticationToken)
                && caller.getAuthorities().stream().anyMatch(g -> g.getAuthority().equals("ROLE_POLICY_ADMIN"));
            return new org.springframework.security.authorization.AuthorizationDecision(allowed);
        })).build();
    }
    @Bean @Order(2)
    SecurityFilterChain operations(HttpSecurity http) throws Exception {
        return http.authorizeHttpRequests(a -> a.requestMatchers("/ops/**").authenticated().anyRequest().denyAll()).build();
    }
}
