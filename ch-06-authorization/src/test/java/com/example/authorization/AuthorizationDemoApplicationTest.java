package com.example.authorization;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Arrays;

import org.junit.jupiter.api.Test;
import org.springframework.aop.support.AopUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authorization.AuthorizationDeniedException;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "demo.password=demo-only-123")
class AuthorizationDemoApplicationTest {

    @Value("${local.server.port}")
    private int port;

    @Autowired
    private DocumentService documents;

    private final HttpClient client = HttpClient.newHttpClient();

    @Test
    void tenantAndOwnerAreBothRequired() throws Exception {
        assertThat(get("alice", "/api/tenants/t1/documents/d1").statusCode()).isEqualTo(200);
        assertThat(get("bob", "/api/tenants/t1/documents/d1").statusCode()).isEqualTo(403);
        assertThat(get("carol", "/api/tenants/t1/documents/d1").statusCode()).isEqualTo(403);
        assertThat(get("alice", "/api/tenants/t2/documents/d1").statusCode()).isEqualTo(403);
        assertThat(get("alice", "/api/tenants/t1/documents/d4").statusCode()).isEqualTo(403);
        assertThat(get("bob", "/api/tenants/t1/documents/d2").statusCode()).isEqualTo(200);
        assertThat(get("carol", "/api/tenants/t2/documents/d3").statusCode()).isEqualTo(200);
    }

    @Test
    void adminRuleAndDefaultDenyApply() throws Exception {
        assertThat(get("admin", "/api/admin/summary").statusCode()).isEqualTo(200);
        assertThat(get("alice", "/api/admin/summary").statusCode()).isEqualTo(403);
        assertThat(get("alice", "/api/not-configured").statusCode()).isEqualTo(403);
        assertThat(get(null, "/api/tenants/t1/documents/d1").statusCode()).isEqualTo(401);
    }

    @Test
    void methodSecurityAlsoRejectsCallsOutsideHttp() {
        authenticate("bob", "ROLE_USER", "TENANT_t1");
        try {
            assertThatThrownBy(() -> this.documents.read("t1", "d1"))
                    .isInstanceOf(AuthorizationDeniedException.class);
            assertThatThrownBy(() -> this.documents.adminSummary())
                    .isInstanceOf(AuthorizationDeniedException.class);
        }
        finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    void methodSecurityRejectsOwnerOutsideTenant() {
        authenticate("alice", "ROLE_USER", "TENANT_t1");
        try {
            assertThat(AopUtils.isAopProxy(this.documents)).isTrue();
            assertThatThrownBy(() -> this.documents.read("t2", "d4"))
                    .isInstanceOf(AuthorizationDeniedException.class);
        }
        finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    void methodSecurityAllowsTenantMemberToReadOwnDocument() {
        try {
            authenticate("alice", "ROLE_USER", "TENANT_t1");
            assertThat(this.documents.read("t1", "d1").id()).isEqualTo("d1");
            authenticate("carol", "ROLE_USER", "TENANT_t2");
            assertThat(this.documents.read("t2", "d3").id()).isEqualTo("d3");
        }
        finally {
            SecurityContextHolder.clearContext();
        }
    }

    @Test
    void methodSecurityChecksResourceTenantAndOwnerOutsideHttp() {
        authenticate("alice", "ROLE_USER", "TENANT_t1");
        try {
            assertThatThrownBy(() -> this.documents.read("t1", "d2"))
                    .isInstanceOf(AuthorizationDeniedException.class);
            assertThatThrownBy(() -> this.documents.read("t1", "d4"))
                    .isInstanceOf(AuthorizationDeniedException.class);
        }
        finally {
            SecurityContextHolder.clearContext();
        }
    }

    private void authenticate(String username, String... authorities) {
        SecurityContext context = SecurityContextHolder.createEmptyContext();
        context.setAuthentication(UsernamePasswordAuthenticationToken.authenticated(username, null,
                Arrays.stream(authorities).map(SimpleGrantedAuthority::new).toList()));
        SecurityContextHolder.setContext(context);
    }

    private HttpResponse<String> get(String username, String path) throws Exception {
        HttpRequest.Builder request = HttpRequest.newBuilder(URI.create("http://localhost:" + this.port + path)).GET();
        if (username != null) {
            String credentials = username + ":demo-only-123";
            String basic = Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
            request.header("Authorization", "Basic " + basic);
        }
        return this.client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }
}
