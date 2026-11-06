package com.example.multichain;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;

class DemoLoginThrottleTest {

    @Test
    void sixteenthAttemptFromSameAddressIsRejected() throws Exception {
        DemoLoginThrottle throttle = new DemoLoginThrottle();
        for (int attempt = 1; attempt <= 16; attempt++) {
            MockHttpServletRequest request = new MockHttpServletRequest("POST", "/api/v1/admin/session");
            request.setRemoteAddr("192.0.2.10");
            MockHttpServletResponse response = new MockHttpServletResponse();
            MockFilterChain chain = new MockFilterChain();
            throttle.doFilter(request, response, chain);
            if (attempt <= 15) {
                assertThat(chain.getRequest()).isNotNull();
            }
            else {
                assertThat(response.getStatus()).isEqualTo(429);
                assertThat(chain.getRequest()).isNull();
            }
        }
    }
}
