package com.example.sms;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collection;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationConverter;
import org.springframework.security.web.authentication.AuthenticationFilter;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfAuthenticationStrategy;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class SmsLoginApplication {
    private static final String DEMO_PHONE = "13800138000";

    public static void main(String[] args) {
        SpringApplication.run(SmsLoginApplication.class, args);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    UserDetailsService users(PasswordEncoder encoder) {
        UserDetails user = User.withUsername(DEMO_PHONE)
                .password(encoder.encode(java.util.UUID.randomUUID().toString()))
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    SmsCodes smsCodes(@Value("${demo.sms.code}") String code) {
        return new SmsCodes(DEMO_PHONE, code);
    }

    @Bean
    SecurityFilterChain security(HttpSecurity http, UserDetailsService users,
                                 SmsCodes codes) throws Exception {
        SecurityContextRepository contexts = new HttpSessionSecurityContextRepository();
        CsrfTokenRepository csrfTokens = new HttpSessionCsrfTokenRepository();
        CsrfAuthenticationStrategy rotateCsrf = new CsrfAuthenticationStrategy(csrfTokens);
        AuthenticationProvider smsProvider = new SmsProvider(users, codes);
        AuthenticationFilter smsFilter = new AuthenticationFilter(
                new ProviderManager(smsProvider), new SmsConverter());
        smsFilter.setRequestMatcher(PathPatternRequestMatcher.withDefaults()
                .matcher(HttpMethod.POST, "/login/sms"));
        smsFilter.setSecurityContextRepository(contexts);
        smsFilter.setSuccessHandler(new AuthenticationSuccessHandler() {
            @Override
            public void onAuthenticationSuccess(HttpServletRequest request,
                    HttpServletResponse response, Authentication authentication) {
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            }

            @Override
            public void onAuthenticationSuccess(HttpServletRequest request,
                    HttpServletResponse response, FilterChain chain,
                    Authentication authentication) {
                rotateCsrf.onAuthentication(authentication, request, response);
                // 停在登录端点，避免默认的四参数方法继续执行过滤器链。
                response.setStatus(HttpServletResponse.SC_NO_CONTENT);
            }
        });
        smsFilter.setFailureHandler((request, response, exception) ->
                response.sendError(HttpServletResponse.SC_UNAUTHORIZED,
                        "Bad credentials"));

        http.securityContext(context -> context.securityContextRepository(contexts));
        http.csrf(csrf -> csrf.csrfTokenRepository(csrfTokens));
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/csrf", "/login/sms").permitAll()
                .anyRequest().authenticated());
        http.exceptionHandling(exceptions -> exceptions.authenticationEntryPoint(
                (request, response, exception) ->
                        response.sendError(HttpServletResponse.SC_UNAUTHORIZED)));
        // CSRF 保持开启；Session 登录需要让客户端先取得并回传 CSRF Token。
        http.addFilterBefore(smsFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    static final class SmsConverter implements AuthenticationConverter {
        @Override
        public Authentication convert(HttpServletRequest request) {
            String phone = request.getParameter("phone");
            String code = request.getParameter("code");
            if (phone == null || phone.isBlank() || code == null || code.isBlank()) {
                throw new BadCredentialsException("Bad credentials");
            }
            return SmsToken.unauthenticated(phone, code);
        }
    }

    static final class SmsToken extends AbstractAuthenticationToken {
        private final Object principal;
        private Object credentials;

        private SmsToken(String phone, String code) {
            super(java.util.List.of());
            this.principal = phone;
            this.credentials = code;
            super.setAuthenticated(false);
        }

        private SmsToken(UserDetails user, Collection<? extends GrantedAuthority> authorities) {
            super(authorities);
            // 只保留身份标识，不把可能与用户仓库共享的可变 UserDetails 放进结果。
            this.principal = user.getUsername();
            this.credentials = null;
            super.setAuthenticated(true);
        }

        static SmsToken unauthenticated(String phone, String code) {
            return new SmsToken(phone, code);
        }

        static SmsToken authenticated(UserDetails user) {
            return new SmsToken(user, user.getAuthorities());
        }

        @Override public Object getPrincipal() { return this.principal; }
        @Override public Object getCredentials() { return this.credentials; }

        @Override
        public void setAuthenticated(boolean authenticated) {
            if (authenticated) {
                throw new IllegalArgumentException("Use SmsToken.authenticated after verification");
            }
            super.setAuthenticated(false);
        }

        @Override
        public void eraseCredentials() {
            super.eraseCredentials();
            this.credentials = null;
        }
    }

    static final class SmsProvider implements AuthenticationProvider {
        private final UserDetailsService users;
        private final SmsCodes codes;

        SmsProvider(UserDetailsService users, SmsCodes codes) {
            this.users = users;
            this.codes = codes;
        }

        @Override
        public Authentication authenticate(Authentication authentication) {
            String phone = authentication.getName();
            String code = String.valueOf(authentication.getCredentials());
            if (!this.codes.consume(phone, code)) {
                throw new BadCredentialsException("Bad credentials");
            }
            try {
                UserDetails user = this.users.loadUserByUsername(phone);
                new AccountStatusUserDetailsChecker().check(user);
                return SmsToken.authenticated(user);
            }
            catch (UsernameNotFoundException ex) {
                throw new BadCredentialsException("Bad credentials", ex);
            }
        }

        @Override
        public boolean supports(Class<?> type) {
            return SmsToken.class.isAssignableFrom(type);
        }
    }

    static final class SmsCodes {
        private record Entry(String code, Instant expiresAt) { }
        private final ConcurrentHashMap<String, Entry> entries = new ConcurrentHashMap<>();

        SmsCodes(String phone, String code) {
            this.entries.put(phone, new Entry(code, Instant.now().plus(3, ChronoUnit.MINUTES)));
        }

        boolean consume(String phone, String code) {
            AtomicBoolean accepted = new AtomicBoolean(false);
            this.entries.computeIfPresent(phone, (key, entry) -> {
                if (!Instant.now().isBefore(entry.expiresAt())) {
                    return null;
                }
                if (entry.code().equals(code)) {
                    accepted.set(true);
                    return null; // 原子消费，一次成功后立即失效
                }
                return entry;
            });
            return accepted.get();
        }
    }

    @RestController
    static class DemoEndpoints {
        @GetMapping("/csrf")
        Map<String, String> csrf(CsrfToken token) {
            return Map.of("headerName", token.getHeaderName(), "token", token.getToken());
        }

        @GetMapping("/me")
        Map<String, String> me(Authentication authentication) {
            return Map.of("name", authentication.getName(),
                    "authenticated", String.valueOf(authentication.isAuthenticated()));
        }
    }
}
