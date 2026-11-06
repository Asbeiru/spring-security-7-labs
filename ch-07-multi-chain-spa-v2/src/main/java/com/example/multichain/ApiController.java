package com.example.multichain;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
class ApiController {

    private final AtomicInteger writes = new AtomicInteger();

    private final AtomicInteger publicWrites = new AtomicInteger();

    @GetMapping("/articles")
    Map<String, String> articles(HttpServletRequest request) {
        return Map.of("viewer", request.getUserPrincipal() == null ? "anonymous" : request.getUserPrincipal().getName());
    }

    // 故意保留这个入口，用回归测试检查公开链是否会阻断新增的 POST。
    @PostMapping("/articles")
    void publicWrite() {
        this.publicWrites.incrementAndGet();
    }

    int publicWriteCount() {
        return this.publicWrites.get();
    }

    @GetMapping("/auth/csrf")
    Map<String, String> csrf(CsrfToken token) {
        return Map.of("token", token.getToken(), "headerName", token.getHeaderName());
    }

    @GetMapping("/admin/session")
    ResponseEntity<Map<String, String>> session(HttpServletRequest request) {
        if (request.getUserPrincipal() == null) {
            return ResponseEntity.status(401).body(Map.of("message", "请先登录"));
        }
        return ResponseEntity.ok(Map.of("username", request.getUserPrincipal().getName()));
    }

    @PostMapping("/admin/articles")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void createArticle() {
        this.writes.incrementAndGet();
    }

    @GetMapping("/admin/articles/count")
    Map<String, Integer> count() {
        return Map.of("count", this.writes.get());
    }
}
