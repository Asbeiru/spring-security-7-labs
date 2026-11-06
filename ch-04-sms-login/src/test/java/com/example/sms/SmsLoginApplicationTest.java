package com.example.sms;

import java.io.IOException;
import java.net.CookieManager;
import java.net.CookiePolicy;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = "demo.sms.code=654321")
class SmsLoginApplicationTest {

    private static final Pattern CSRF_TOKEN = Pattern.compile("\"token\":\"([^\"]+)\"");

    @Value("${local.server.port}")
    private int port;

    @Test
    void loginPersistsIdentityRotatesCsrfAndConsumesCodeOnce() throws Exception {
        CookieManager cookies = new CookieManager(null, CookiePolicy.ACCEPT_ALL);
        try (HttpClient client = HttpClient.newBuilder().cookieHandler(cookies).build()) {
            assertEquals(401, get(client, "/me").statusCode());

            String firstCsrf = csrfToken(get(client, "/csrf"));
            // 匿名请求缺少 CSRF Token 时，当前 AuthenticationEntryPoint 返回 401。
            assertEquals(401, postLogin(client, null, "654321").statusCode());
            assertEquals(401, postLogin(client, firstCsrf, "000000").statusCode());
            assertEquals(204, postLogin(client, firstCsrf, "654321").statusCode());

            HttpResponse<String> me = get(client, "/me");
            assertEquals(200, me.statusCode());
            assertTrue(me.body().contains("\"name\":\"13800138000\""));
            assertTrue(me.body().contains("\"authenticated\":\"true\""));

            assertEquals(403, postLogin(client, firstCsrf, "654321").statusCode());
            String secondCsrf = csrfToken(get(client, "/csrf"));
            assertEquals(401, postLogin(client, secondCsrf, "654321").statusCode());
            assertEquals(200, get(client, "/me").statusCode());
        }
    }

    private HttpResponse<String> get(HttpClient client, String path)
            throws IOException, InterruptedException {
        HttpRequest request = HttpRequest.newBuilder(uri(path)).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> postLogin(HttpClient client, String csrf, String code)
            throws IOException, InterruptedException {
        HttpRequest.Builder request = HttpRequest.newBuilder(uri("/login/sms"))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString("phone=13800138000&code=" + code));
        if (csrf != null) {
            request.header("X-CSRF-TOKEN", csrf);
        }
        return client.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private URI uri(String path) {
        return URI.create("http://localhost:" + this.port + path);
    }

    private static String csrfToken(HttpResponse<String> response) {
        assertEquals(200, response.statusCode());
        Matcher matcher = CSRF_TOKEN.matcher(response.body());
        assertTrue(matcher.find(), "CSRF response has no token: " + response.body());
        return matcher.group(1);
    }
}
