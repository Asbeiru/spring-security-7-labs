package com.zhouzhou.agent.security.config;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * Spring Security 7.x 现代 OAuth 2.1 资源服务器配置
 *
 * 核心特性：
 * 1. 纯无状态 JWT 验签（iss + aud + 时间戳）
 * 2. 7.0 起原生支持的 RFC 9728 保护资源元数据发现
 * 3. 开启方法级安全
 *
 * @author 洲洲
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity // 开启方法级安全（@PreAuthorize / @PostFilter）
public class AgentResourceServerConfig {

    // 7.x 中 HttpSecurity#build() 不再声明受检异常，无需 throws Exception
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) {
        http
            // 1. 禁用 CSRF 与会话（纯无状态 API 服务，令牌通过 Authorization 头传递）
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // 2. 路由访问控制
            .authorizeHttpRequests(authorize -> authorize
                // 公开健康探针
                .requestMatchers("/actuator/health/**").permitAll()
                // 所有业务与 Agent 工具端点：必须持有合法令牌
                // 注：RFC 9728 元数据过滤器位于授权过滤器之前，无需额外 permitAll
                .anyRequest().authenticated()
            )

            // 3. 启用资源服务器 JWT 验签，并定制 RFC 9728 元数据
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                .protectedResourceMetadata(metadata -> metadata
                    .protectedResourceMetadataCustomizer(builder -> builder
                        // resource 默认由请求 URL 推导，这里只补充授权服务器、Scope 与名称
                        .authorizationServer("https://auth.zhouzhou.com")
                        .scope("mcp:analytics:read")
                        .scope("mcp:vault:transfer")
                        .scope("mcp:rag:query")
                        .tlsClientCertificateBoundAccessTokens(false)
                        .resourceName("Zhouzhou Vault Agent API")
                    )
                )
                // 如客户端支持，可开启 DPoP 绑定令牌：.dPoP(Customizer.withDefaults())
            );

        return http.build();
    }

    private JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtGrantedAuthoritiesConverter scopeConverter = new JwtGrantedAuthoritiesConverter();
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(jwt -> {
            Collection<GrantedAuthority> authorities = new ArrayList<>(scopeConverter.convert(jwt));
            List<String> roles = jwt.getClaimAsStringList("roles");
            if (roles != null) {
                roles.forEach(role -> authorities.add(new SimpleGrantedAuthority("ROLE_" + role)));
            }
            return authorities;
        });
        return converter;
    }
}
