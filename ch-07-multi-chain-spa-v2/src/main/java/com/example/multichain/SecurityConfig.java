package com.example.multichain;

import java.time.Clock;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.context.NullSecurityContextRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;

@Configuration
class SecurityConfig {

    @Bean
    @Order(1)
    SecurityFilterChain publicRead(HttpSecurity http) throws Exception {
        http.securityMatcher("/api/v1/articles", "/api/v1/articles/**");
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers(HttpMethod.GET, "/**").permitAll()
                .requestMatchers(HttpMethod.HEAD, "/**").permitAll()
                .anyRequest().denyAll());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
        http.securityContext(context -> context.securityContextRepository(new NullSecurityContextRepository()));
        http.csrf(csrf -> csrf.disable());
        http.requestCache(cache -> cache.disable());
        http.exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint((request, response, exception) -> SecurityResponses.error(response, 403))
                .accessDeniedHandler((request, response, exception) -> SecurityResponses.error(response, 403)));
        return http.build();
    }

    @Bean
    @Order(2)
    SecurityFilterChain admin(HttpSecurity http, LoginAttemptCounter counter, ClientAddress address)
            throws Exception {
        http.addFilterBefore(new LoginThrottle(counter, address), UsernamePasswordAuthenticationFilter.class);
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/api/v1/auth/csrf", "/api/v1/admin/session", "/error").permitAll()
                .requestMatchers("/api/v1/admin/**").hasRole("ADMIN")
                .anyRequest().denyAll());
        http.sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED));
        http.csrf(csrf -> csrf.csrfTokenRepository(new HttpSessionCsrfTokenRepository()));
        http.formLogin(form -> form.loginProcessingUrl("/api/v1/admin/session")
                .successHandler((request, response, authentication) -> response.setStatus(204))
                .failureHandler((request, response, exception) -> SecurityResponses.error(response, 401)));
        http.logout(logout -> logout.logoutUrl("/api/v1/admin/logout")
                .logoutSuccessHandler((request, response, authentication) -> response.setStatus(204)));
        http.exceptionHandling(exceptions -> exceptions
                .authenticationEntryPoint((request, response, exception) -> SecurityResponses.error(response, 401))
                .accessDeniedHandler((request, response, exception) -> SecurityResponses.error(response, 403)));
        http.requestCache(cache -> cache.disable());
        return http.build();
    }

    @Bean
    ClientAddress clientAddress(@Value("${demo.trusted-proxy-cidrs:}") String cidrs) {
        return new ClientAddress(cidrs);
    }

    @Bean
    @ConditionalOnProperty(name = "demo.login-counter", havingValue = "memory", matchIfMissing = true)
    InMemoryLoginAttemptCounter memoryCounter() {
        return new InMemoryLoginAttemptCounter(Clock.systemUTC());
    }

    @Bean
    @ConditionalOnProperty(name = "demo.login-counter", havingValue = "redis")
    RedisLoginAttemptCounter redisCounter(StringRedisTemplate redis) {
        return new RedisLoginAttemptCounter(redis);
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    UserDetailsService users(PasswordEncoder encoder, @Value("${demo.password}") String password) {
        return new InMemoryUserDetailsManager(
                User.withUsername("admin").password(encoder.encode(password)).roles("ADMIN").build(),
                User.withUsername("reader").password(encoder.encode(password)).roles("USER").build());
    }
}
