package com.zhouzhou.assistant.bonus;

import jakarta.servlet.*;
import java.util.*;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.*;
import org.springframework.context.annotation.*;
import org.springframework.mock.web.*;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.*;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.web.context.support.AnnotationConfigWebApplicationContext;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import static com.zhouzhou.assistant.bonus.AgentSecurity.*;
import static org.assertj.core.api.Assertions.*;

class ControlSecurityTest {
    @Configuration @EnableWebSecurity @Import(ControlSecurity.class) static class App {}
    AnnotationConfigWebApplicationContext context;
    @BeforeEach void open() {
        context = new AnnotationConfigWebApplicationContext(); context.setServletContext(new MockServletContext()); context.register(App.class); context.refresh();
    }
    @AfterEach void close() { SecurityContextHolder.clearContext(); context.close(); }
    int invoke(String path, org.springframework.security.core.Authentication auth) throws Exception {
        // Synthetic authenticated ingress, not an OAuth/JWT authentication integration test.
        var request = new MockHttpServletRequest("GET", path); request.setServletPath(path);
        var response = new MockHttpServletResponse();
        AtomicInteger controllerEffects = new AtomicInteger();
        var proxy = context.getBean(FilterChainProxy.class);
        var sc = SecurityContextHolder.createEmptyContext(); sc.setAuthentication(auth);
        var session = new MockHttpSession();
        session.setAttribute(org.springframework.security.web.context.HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY, sc);
        request.setSession(session);
        proxy.doFilter(request, response, (req, res) -> controllerEffects.incrementAndGet());
        if (response.getStatus() == 403) assertThat(controllerEffects.get()).isZero();
        return response.getStatus();
    }
    @Test void agentCanReachOperationsButCannotModifyPolicy() throws Exception {
        var agent = new DelegationAuthenticationToken(new Identity("main", "root"));
        assertThat(invoke("/ops/read", agent)).isEqualTo(200);
        assertThat(invoke("/control/policies", agent)).isEqualTo(403);
        assertThat(invoke("/unknown", agent)).isEqualTo(403);
    }
    @Test void onlyTrustedAdministratorCanReachControlChain() throws Exception {
        var admin = UsernamePasswordAuthenticationToken.authenticated("admin", "", List.of(new SimpleGrantedAuthority("ROLE_POLICY_ADMIN")));
        var user = UsernamePasswordAuthenticationToken.authenticated("alice", "", List.of());
        assertThat(invoke("/control/policies", user)).isEqualTo(403);
        assertThat(invoke("/control/policies", admin)).isEqualTo(200);
    }
}
