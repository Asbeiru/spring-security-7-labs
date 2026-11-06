package com.example.multichain;

import java.io.IOException;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

final class DemoLoginThrottle extends OncePerRequestFilter {

    private static final int LIMIT = 15;

    private static final Duration WINDOW = Duration.ofMinutes(15);

    private final ConcurrentHashMap<String, Window> attempts = new ConcurrentHashMap<>();

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !"POST".equals(request.getMethod())
                || !"/api/v1/admin/session".equals(request.getRequestURI());
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Instant now = Instant.now();
        Window current = this.attempts.compute(request.getRemoteAddr(), (key, previous) -> {
            if (previous == null || !now.isBefore(previous.expiresAt())) {
                return new Window(1, now.plus(WINDOW));
            }
            return new Window(previous.count() + 1, previous.expiresAt());
        });
        if (current.count() > LIMIT) {
            response.sendError(429);
            return;
        }
        chain.doFilter(request, response);
    }

    private record Window(int count, Instant expiresAt) {
    }
}
