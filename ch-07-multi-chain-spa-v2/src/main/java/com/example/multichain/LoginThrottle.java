package com.example.multichain;

import java.io.IOException;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.http.HttpMethod;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

final class LoginThrottle extends OncePerRequestFilter {

    private final RequestMatcher loginRequest = PathPatternRequestMatcher.withDefaults()
            .matcher(HttpMethod.POST, "/api/v1/admin/session");

    private final LoginAttemptCounter counter;

    private final ClientAddress address;

    LoginThrottle(LoginAttemptCounter counter, ClientAddress address) {
        this.counter = counter;
        this.address = address;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !this.loginRequest.matches(request);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        Long count;
        try {
            count = this.counter.increment(this.address.get(request));
            if (count == null) {
                throw new IllegalStateException("Login counter returned no result");
            }
        }
        catch (RuntimeException exception) {
            SecurityResponses.error(response, 503);
            return;
        }
        if (count > 15) {
            SecurityResponses.error(response, 429);
            return;
        }
        chain.doFilter(request, response);
    }
}
