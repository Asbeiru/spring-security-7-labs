package com.example.session;

import java.io.IOException;
import java.net.CookieManager;
import java.net.HttpCookie;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "demo.password=demo-only-123")
class SessionDemoApplicationTest {

    private static final Pattern CSRF_INPUT = Pattern.compile(
            "name=\"_csrf\"[^>]*value=\"([^\"]+)\"");

    @Value("${local.server.port}")
    private int port;

    @Test
    void loginRotatesSessionIdAndRejectsSecondConcurrentLogin() throws Exception {
        Browser first = new Browser(port);
        Browser second = new Browser(port);

        String firstCsrf = first.csrfFromLoginPage();
        String originalSessionId = first.sessionId();
        assertThat(originalSessionId).isNotBlank();
        assertThat(first.get("/me").statusCode()).isEqualTo(302);

        assertThat(first.login(firstCsrf).statusCode()).isEqualTo(302);
        assertThat(first.sessionId()).isNotEqualTo(originalSessionId);
        assertThat(first.get("/me").body()).contains("\"name\":\"zhouzhou\"");

        String secondCsrf = second.csrfFromLoginPage();
        HttpResponse<String> rejected = second.login(secondCsrf);
        assertThat(rejected.statusCode()).isEqualTo(302);
        assertThat(rejected.headers().firstValue("Location").orElseThrow())
                .endsWith("/login?error");
        assertThat(second.get("/me").statusCode()).isEqualTo(302);
        assertThat(first.get("/me").statusCode()).isEqualTo(200);

        String logoutCsrf = first.csrfFromPage("/logout");
        assertThat(first.post("/logout", "_csrf="
                + URLEncoder.encode(logoutCsrf, StandardCharsets.UTF_8)).statusCode())
                .isEqualTo(302);
        assertThat(first.get("/me").statusCode()).isEqualTo(302);

        assertThat(second.login(second.csrfFromLoginPage()).statusCode()).isEqualTo(302);
        assertThat(second.get("/me").statusCode()).isEqualTo(200);
    }

    @Test
    void loginWithoutCsrfTokenDoesNotAuthenticate() throws Exception {
        Browser browser = new Browser(port);
        HttpResponse<String> response = browser.post("/login", "username=zhouzhou&password=demo-only-123");
        assertThat(response.statusCode()).isEqualTo(302);
        assertThat(response.headers().firstValue("Location").orElseThrow()).contains("/login");
        assertThat(browser.get("/me").statusCode()).isEqualTo(302);
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

        String csrfFromLoginPage() throws IOException, InterruptedException {
            return csrfFromPage("/login");
        }

        String csrfFromPage(String path) throws IOException, InterruptedException {
            HttpResponse<String> page = get(path);
            assertThat(page.statusCode()).isEqualTo(200);
            Matcher matcher = CSRF_INPUT.matcher(page.body());
            assertThat(matcher.find()).isTrue();
            return matcher.group(1);
        }

        String sessionId() {
            return this.cookies.getCookieStore().getCookies().stream()
                    .filter(cookie -> cookie.getName().equals("JSESSIONID"))
                    .map(HttpCookie::getValue)
                    .findFirst()
                    .orElse(null);
        }

        HttpResponse<String> login(String csrf) throws IOException, InterruptedException {
            return post("/login", "username=zhouzhou&password=demo-only-123&_csrf="
                    + URLEncoder.encode(csrf, StandardCharsets.UTF_8));
        }

        HttpResponse<String> get(String path) throws IOException, InterruptedException {
            return send(HttpRequest.newBuilder(this.base.resolve(path)).GET().build());
        }

        HttpResponse<String> post(String path, String form) throws IOException, InterruptedException {
            HttpRequest request = HttpRequest.newBuilder(this.base.resolve(path))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .POST(HttpRequest.BodyPublishers.ofString(form))
                    .build();
            return send(request);
        }

        private HttpResponse<String> send(HttpRequest request) throws IOException, InterruptedException {
            return this.client.send(request, HttpResponse.BodyHandlers.ofString());
        }
    }
}
