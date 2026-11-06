package com.example.multichain;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class LoginThrottleTest {

    @Test
    void exceededCountReturnsJson429WithoutContinuingAuthentication() throws Exception {
        assertBlocked(ip -> 16L, 429, "登录尝试过多");
    }

    @Test
    void counterFailureReturnsJson503WithoutContinuingAuthentication() throws Exception {
        assertBlocked(ip -> { throw new IllegalStateException("backend unavailable"); }, 503, "登录服务暂不可用");
    }

    @Test
    void missingCounterResultReturns503InsteadOfReportingAQuotaViolation() throws Exception {
        assertBlocked(ip -> null, 503, "登录服务暂不可用");
    }

    @Test
    void loginMatcherWorksUnderAContextPathAndSkipsOtherRequests() throws Exception {
        int[] calls = {0};
        LoginThrottle throttle = new LoginThrottle(ip -> (long) ++calls[0], new ClientAddress(""));
        MockHttpServletRequest request = loginRequest();
        request.setContextPath("/site");
        request.setRequestURI("/site/api/v1/admin/session");
        throttle.doFilter(request, new MockHttpServletResponse(), new MockFilterChain());
        assertThat(calls[0]).isEqualTo(1);
        MockHttpServletRequest get = new MockHttpServletRequest("GET", "/api/v1/admin/session");
        get.setServletPath("/api/v1/admin/session");
        throttle.doFilter(get, new MockHttpServletResponse(), new MockFilterChain());
        assertThat(calls[0]).isEqualTo(1);
    }

    private static void assertBlocked(LoginAttemptCounter counter, int status, String message) throws Exception {
        LoginThrottle throttle = new LoginThrottle(counter, new ClientAddress(""));
        MockHttpServletResponse response = new MockHttpServletResponse();
        MockFilterChain chain = new MockFilterChain();
        throttle.doFilter(loginRequest(), response, chain);
        assertThat(response.getStatus()).isEqualTo(status);
        assertThat(response.getContentType()).contains("application/json");
        assertThat(response.getContentAsString()).contains(message);
        assertThat(chain.getRequest()).isNull();
    }

    private static MockHttpServletRequest loginRequest() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/admin/session");
        request.setServletPath("/api/v1/admin/session");
        request.setRemoteAddr("192.0.2.1");
        return request;
    }
}
