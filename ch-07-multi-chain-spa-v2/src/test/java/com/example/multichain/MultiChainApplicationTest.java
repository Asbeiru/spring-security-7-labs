package com.example.multichain;

import java.net.CookieManager;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "demo.password=demo-only-123")
class MultiChainApplicationTest {

    @Value("${local.server.port}")
    private int port;

    @Autowired
    private InMemoryLoginAttemptCounter counter;

    @Autowired
    private ApiController controller;

    @BeforeEach
    void clearAttempts() {
        this.counter.clear();
    }

    @Test
    void publicGetAndHeadDoNotCreateSession() throws Exception {
        Browser browser = new Browser(this.port);
        HttpResponse<String> response = browser.get("/api/v1/articles");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("\"viewer\":\"anonymous\"");
        assertThat(response.headers().allValues("Set-Cookie")).isEmpty();
        assertThat(browser.request("HEAD", "/api/v1/articles", null, "").statusCode()).isEqualTo(200);
        assertThat(browser.sessionId()).isNull();
    }

    @Test
    void publicPostStopsBeforeControllerAndDoesNotFallThrough() throws Exception {
        Browser browser = new Browser(this.port);
        browser.login("admin");
        int before = this.controller.publicWriteCount();
        HttpResponse<String> response = browser.post("/api/v1/articles", browser.csrf(), "");
        assertThat(response.statusCode()).isEqualTo(403);
        assertThat(response.body()).contains("权限不足或请求验证失败");
        assertThat(this.controller.publicWriteCount()).isEqualTo(before);
    }

    @Test
    void publicChainDoesNotRestoreAdministratorFromCookie() throws Exception {
        Browser browser = new Browser(this.port);
        browser.login("admin");
        assertThat(browser.get("/api/v1/admin/session").body()).contains("admin");
        assertThat(browser.get("/api/v1/articles").body()).contains("\"viewer\":\"anonymous\"");
    }

    @Test
    void loginRotatesSessionAndOldCsrfCannotWrite() throws Exception {
        Browser browser = new Browser(this.port);
        String beforeLogin = browser.csrf();
        String oldSession = browser.sessionId();
        assertThat(browser.post("/api/v1/admin/session", beforeLogin,
                "username=admin&password=demo-only-123").statusCode()).isEqualTo(204);
        assertThat(browser.sessionId()).isNotEqualTo(oldSession);
        assertThat(browser.post("/api/v1/admin/articles", beforeLogin, "").statusCode()).isEqualTo(403);
        assertThat(browser.post("/api/v1/admin/articles", browser.csrf(), "").statusCode()).isEqualTo(204);
    }

    @Test
    void xorMasksChangeWhileBothRepresentTheCurrentValidToken() throws Exception {
        Browser browser = new Browser(this.port);
        browser.login("admin");
        String first = browser.csrf();
        String second = browser.csrf();
        assertThat(first).isNotEqualTo(second);
        assertThat(browser.post("/api/v1/admin/articles", first, "").statusCode()).isEqualTo(204);
        assertThat(browser.post("/api/v1/admin/articles", second, "").statusCode()).isEqualTo(204);
    }

    @Test
    void logoutClearsIdentityAndOldCsrfCannotBeUsedToLogin() throws Exception {
        Browser browser = new Browser(this.port);
        browser.login("admin");
        String token = browser.csrf();
        assertThat(browser.post("/api/v1/admin/logout", token, "").statusCode()).isEqualTo(204);
        assertThat(browser.get("/api/v1/admin/session").statusCode()).isEqualTo(401);
        assertThat(browser.post("/api/v1/admin/session", token,
                "username=admin&password=demo-only-123").statusCode()).isEqualTo(403);
        browser.login("admin");
    }

    @Test
    void missingCsrfIsRejectedBeforeLoginThrottle() throws Exception {
        Browser browser = new Browser(this.port);
        for (int attempt = 0; attempt < 16; attempt++) {
            assertThat(browser.post("/api/v1/admin/session", null,
                    "username=admin&password=demo-only-123").statusCode()).isEqualTo(403);
        }
        browser.login("admin");
    }

    @Test
    void sixteenthCsrfValidLoginAttemptReturnsJson429() throws Exception {
        Browser browser = new Browser(this.port);
        String token = browser.csrf();
        for (int attempt = 1; attempt <= 15; attempt++) {
            HttpResponse<String> response = browser.post("/api/v1/admin/session", token,
                    "username=admin&password=wrong");
            assertThat(response.statusCode()).as("attempt %s", attempt).isEqualTo(401);
            assertThat(response.body()).contains("用户名与密码");
        }
        HttpResponse<String> response = browser.post("/api/v1/admin/session", token,
                "username=admin&password=wrong");
        assertThat(response.statusCode()).isEqualTo(429);
        assertThat(response.headers().firstValue("Content-Type").orElse("")).contains("application/json");
        assertThat(response.body()).isEqualTo("{\"message\":\"登录尝试过多，请稍后再试\"}");
    }

    @Test
    void roleDenialIs403WhileSessionAndCsrfRemainValid() throws Exception {
        Browser browser = new Browser(this.port);
        browser.login("reader");
        String token = browser.csrf();
        assertThat(browser.post("/api/v1/admin/articles", token, "").statusCode()).isEqualTo(403);
        HttpResponse<String> session = browser.get("/api/v1/admin/session");
        assertThat(session.statusCode()).isEqualTo(200);
        assertThat(session.body()).contains("reader");
    }

    @Test
    void anonymousProtectedGetIs401WithoutRedirect() throws Exception {
        HttpResponse<String> response = new Browser(this.port).get("/api/v1/admin/articles/count");
        assertThat(response.statusCode()).isEqualTo(401);
        assertThat(response.headers().firstValue("Location")).isEmpty();
        assertThat(response.body()).contains("message");
    }

    private static final class Browser {

        private static final Pattern TOKEN = Pattern.compile("\"token\":\"([^\"]+)\"");

        private final URI base;

        private final CookieManager cookies = new CookieManager();

        private final HttpClient client = HttpClient.newBuilder()
                .cookieHandler(this.cookies)
                .followRedirects(HttpClient.Redirect.NEVER)
                .connectTimeout(Duration.ofSeconds(5))
                .build();

        Browser(int port) {
            this.base = URI.create("http://127.0.0.1:" + port);
        }

        String sessionId() {
            return this.cookies.getCookieStore().getCookies().stream()
                    .filter(cookie -> cookie.getName().equals("JSESSIONID"))
                    .map(java.net.HttpCookie::getValue).findFirst().orElse(null);
        }

        void login(String username) throws Exception {
            assertThat(post("/api/v1/admin/session", csrf(),
                    "username=" + username + "&password=demo-only-123").statusCode()).isEqualTo(204);
        }

        String csrf() throws Exception {
            HttpResponse<String> response = get("/api/v1/auth/csrf");
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(response.body()).contains("\"headerName\":\"X-CSRF-TOKEN\"");
            Matcher match = TOKEN.matcher(response.body());
            assertThat(match.find()).isTrue();
            return match.group(1);
        }

        HttpResponse<String> get(String path) throws Exception {
            return request("GET", path, null, "");
        }

        HttpResponse<String> post(String path, String token, String body) throws Exception {
            return request("POST", path, token, body);
        }

        HttpResponse<String> request(String method, String path, String token, String body) throws Exception {
            HttpRequest.Builder request = HttpRequest.newBuilder(this.base.resolve(path))
                    .header("Content-Type", "application/x-www-form-urlencoded");
            if (token != null) {
                request.header("X-CSRF-TOKEN", token);
            }
            request.method(method, HttpRequest.BodyPublishers.ofString(body));
            return this.client.send(request.build(), HttpResponse.BodyHandlers.ofString());
        }
    }
}
