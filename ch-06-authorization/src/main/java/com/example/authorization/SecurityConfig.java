package com.example.authorization;

import jakarta.servlet.DispatcherType;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;

@Configuration
class SecurityConfig {

    @Bean
    SecurityFilterChain security(HttpSecurity http, TenantAuthorizationManager tenantAccess) throws Exception {
        PathPatternRequestMatcher.Builder paths = PathPatternRequestMatcher.withDefaults();
        http.authorizeHttpRequests(authorize -> authorize
                .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                .requestMatchers(paths.matcher(HttpMethod.GET, "/api/admin/summary")).hasRole("ADMIN")
                .requestMatchers(paths.matcher(HttpMethod.GET,
                        "/api/tenants/{tenantId}/documents/{documentId}")).access(tenantAccess)
                .anyRequest().denyAll());
        http.httpBasic(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    UserDetailsService users(PasswordEncoder encoder, @Value("${demo.password}") String password) {
        String encoded = encoder.encode(password);
        return new InMemoryUserDetailsManager(
                User.withUsername("alice").password(encoded).authorities("ROLE_USER", "TENANT_t1").build(),
                User.withUsername("bob").password(encoded).authorities("ROLE_USER", "TENANT_t1").build(),
                User.withUsername("carol").password(encoded).authorities("ROLE_USER", "TENANT_t2").build(),
                User.withUsername("admin").password(encoded).authorities("ROLE_ADMIN").build());
    }
}
