package com.example.multichain;

import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.security.web.csrf.CsrfToken;

@RestController
@RequestMapping("/api/v1")
class ApiController {

    private final AtomicInteger writes = new AtomicInteger();

    @GetMapping("/articles")
    Map<String, String> articles(HttpServletRequest request) {
        return Map.of("viewer", request.getUserPrincipal() == null ? "anonymous" : request.getUserPrincipal().getName());
    }

    @GetMapping("/auth/csrf")
    Map<String, String> csrf(CsrfToken token) {
        return Map.of("token", token.getToken(), "headerName", token.getHeaderName());
    }

    @GetMapping("/admin/session")
    Map<String, String> session(HttpServletRequest request) {
        if (request.getUserPrincipal() == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED);
        }
        return Map.of("username", request.getUserPrincipal().getName());
    }

    @PostMapping("/admin/items")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    void createItem() {
        this.writes.incrementAndGet();
    }

    @GetMapping("/admin/items/count")
    Map<String, Integer> count() {
        return Map.of("count", this.writes.get());
    }
}
