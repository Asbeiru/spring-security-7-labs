package com.example.multichain;

import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "demo.password=demo-only-123")
class MultiChainApplicationTest {

    private static final Pattern TOKEN = Pattern.compile("\"token\":\"([^\"]+)\"");

    @Value("${local.server.port}")
    private int port;

    @Test
    void publicReadAndAdminSpaFollowDifferentSecurityChains() throws Exception {
        Browser browser = new Browser(this.port);

        HttpResponse<String> publicRead = browser.get("/api/v1/articles");
        assertThat(publicRead.statusCode()).isEqualTo(200);
        assertThat(publicRead.body()).contains("\"viewer\":\"anonymous\"");
        assertThat(browser.hasSessionCookie()).isFalse();
        assertThat(browser.post("/api/v1/articles", null, "").statusCode()).isEqualTo(403);

        String beforeLogin = browser.csrf();
        assertThat(browser.hasSessionCookie()).isTrue();
        assertThat(browser.get("/api/v1/admin/session").statusCode()).isEqualTo(401);
        for (int attempt = 0; attempt < 16; attempt++) {
            assertThat(browser.post("/api/v1/admin/session", null,
                    "username=admin&password=demo-only-123").statusCode()).isEqualTo(403);
        }

        assertThat(browser.post("/api/v1/admin/session", beforeLogin,
                "username=admin&password=demo-only-123").statusCode()).isEqualTo(204);
        assertThat(browser.get("/api/v1/admin/session").body()).contains("\"username\":\"admin\"");
        assertThat(browser.get("/api/v1/articles").body()).contains("\"viewer\":\"anonymous\"");

        assertThat(browser.post("/api/v1/admin/items", beforeLogin, "").statusCode()).isEqualTo(403);
        String afterLogin = browser.csrf();
        assertThat(afterLogin).isNotEqualTo(beforeLogin);
        assertThat(browser.post("/api/v1/admin/items", afterLogin, "").statusCode()).isEqualTo(204);
        assertThat(browser.get("/api/v1/admin/items/count").body()).contains("\"count\":1");
        assertThat(browser.post("/api/v1/articles", afterLogin, "").statusCode()).isEqualTo(403);

        assertThat(browser.post("/api/v1/admin/logout", afterLogin, "").statusCode()).isEqualTo(204);
        assertThat(browser.get("/api/v1/admin/session").statusCode()).isEqualTo(401);
        assertThat(browser.csrf()).isNotEqualTo(afterLogin);
    }

    private static final class Browser {

        private final URI base;

        private final CookieManager cookies = new CookieManager();

        private final HttpClient client = HttpClient.newBuilder()
                .cookieHandler(this.cookies)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        Browser(int port) {
            this.base = URI.create("http://localhost:" + port);
        }

        boolean hasSessionCookie() {
            return this.cookies.getCookieStore().getCookies().stream()
                    .anyMatch(cookie -> cookie.getName().equals("JSESSIONID"));
        }

        String csrf() throws Exception {
            HttpResponse<String> response = get("/api/v1/auth/csrf");
            assertThat(response.statusCode()).isEqualTo(200);
            Matcher match = TOKEN.matcher(response.body());
            assertThat(match.find()).isTrue();
            return match.group(1);
        }

        HttpResponse<String> get(String path) throws Exception {
            return send(HttpRequest.newBuilder(this.base.resolve(path)).GET().build());
        }

        HttpResponse<String> post(String path, String csrf, String body) throws Exception {
            HttpRequest.Builder request = HttpRequest.newBuilder(this.base.resolve(path))
                    .header("Content-Type", "application/x-www-form-urlencoded");
            if (csrf != null) {
                request.header("X-CSRF-TOKEN", csrf);
            }
            return send(request.POST(HttpRequest.BodyPublishers.ofString(body)).build());
        }

        private HttpResponse<String> send(HttpRequest request) throws Exception {
            return this.client.send(request, HttpResponse.BodyHandlers.ofString());
        }
    }
}
