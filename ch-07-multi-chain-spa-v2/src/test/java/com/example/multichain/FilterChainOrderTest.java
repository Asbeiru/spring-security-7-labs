package com.example.multichain;

import org.junit.jupiter.api.Test;
import org.springframework.context.annotation.Bean;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.core.annotation.Order;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.UnreachableFilterChainException;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;

class FilterChainOrderTest {

    @Test
    void defaultCatchAllBeforeAnotherChainFailsAtStartup() {
        try (AnnotationConfigWebApplicationContext context = context(DefaultCatchAllFirst.class)) {
            assertThatThrownBy(context::refresh).hasRootCauseInstanceOf(UnreachableFilterChainException.class);
        }
    }

    @Test
    void explicitWidePatternCanSilentlyShadowNarrowChain() throws Exception {
        try (AnnotationConfigWebApplicationContext context = context(ExplicitWidePatternFirst.class)) {
            context.refresh();
            FilterChainProxy proxy = context.getBean("springSecurityFilterChain", FilterChainProxy.class);
            MockHttpServletRequest request = request();
            assertThat(proxy.getFilterChains()).allMatch(chain -> chain.matches(request));
            MockHttpServletResponse response = new MockHttpServletResponse();
            proxy.doFilter(request, response, (req, res) -> ((jakarta.servlet.http.HttpServletResponse) res).setStatus(204));
            assertThat(response.getStatus()).isEqualTo(204);
        }
    }

    @Test
    void defaultSingleChainCanHandlePublicGetWithoutReadingSession() throws Exception {
        try (AnnotationConfigWebApplicationContext context = context(SinglePublicChain.class)) {
            context.refresh();
            FilterChainProxy proxy = context.getBean("springSecurityFilterChain", FilterChainProxy.class);
            MockHttpServletRequest request = spy(request());
            MockHttpServletResponse response = new MockHttpServletResponse();
            proxy.doFilter(request, response, (req, res) -> ((jakarta.servlet.http.HttpServletResponse) res).setStatus(204));
            assertThat(response.getStatus()).isEqualTo(204);
            verify(request, never()).getSession(anyBoolean());
            verify(request, never()).getSession();
        }
    }

    private static AnnotationConfigWebApplicationContext context(Class<?> config) {
        AnnotationConfigWebApplicationContext context = new AnnotationConfigWebApplicationContext();
        context.setServletContext(new MockServletContext());
        context.register(config);
        return context;
    }

    private static MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest("GET", "/api/v1/articles");
        request.setServletPath("/api/v1/articles");
        return request;
    }

    @TestConfiguration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class DefaultCatchAllFirst {

        @Bean
        @Order(1)
        SecurityFilterChain wide(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll()).build();
        }

        @Bean
        @Order(2)
        SecurityFilterChain narrow(HttpSecurity http) throws Exception {
            return http.securityMatcher("/api/v1/articles/**")
                    .authorizeHttpRequests(auth -> auth.anyRequest().denyAll()).build();
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class ExplicitWidePatternFirst {

        @Bean
        @Order(1)
        SecurityFilterChain wide(HttpSecurity http) throws Exception {
            return http.securityMatcher("/**")
                    .authorizeHttpRequests(auth -> auth.anyRequest().permitAll()).build();
        }

        @Bean
        @Order(2)
        SecurityFilterChain narrow(HttpSecurity http) throws Exception {
            return http.securityMatcher("/api/v1/articles/**")
                    .authorizeHttpRequests(auth -> auth.anyRequest().denyAll()).build();
        }
    }

    @TestConfiguration(proxyBeanMethods = false)
    @EnableWebSecurity
    static class SinglePublicChain {

        @Bean
        SecurityFilterChain single(HttpSecurity http) throws Exception {
            return http.authorizeHttpRequests(auth -> auth.anyRequest().permitAll())
                    .formLogin(Customizer.withDefaults()).build();
        }
    }
}
