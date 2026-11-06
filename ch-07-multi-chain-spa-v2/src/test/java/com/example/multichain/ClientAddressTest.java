package com.example.multichain;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;

class ClientAddressTest {

    @Test
    void untrustedPeerCannotChooseItsRateLimitKeyThroughHeaders() {
        MockHttpServletRequest request = request("198.51.100.20", "192.0.2.10");
        request.addHeader("X-Forwarded-For", "192.0.2.99");
        assertThat(new ClientAddress("10.20.0.0/16").get(request)).isEqualTo("198.51.100.20");
    }

    @Test
    void trustedPeerCanSupplyValidatedCustomHeader() {
        assertThat(new ClientAddress("10.20.0.0/16").get(request("10.20.0.2", "192.0.2.10")))
                .isEqualTo("192.0.2.10");
    }

    @ParameterizedTest
    @ValueSource(strings = {"...", "1.2.3", "999.1.2.3", "01.2.3.4", "example.com", "::xyz", "192.0.2.1, 192.0.2.2"})
    void invalidHeaderFallsBackToDirectPeer(String forwarded) {
        assertThat(new ClientAddress("10.20.0.0/16").get(request("10.20.0.2", forwarded)))
                .isEqualTo("10.20.0.2");
    }

    @Test
    void equivalentIpv6LiteralsProduceTheSameKey() {
        ClientAddress address = new ClientAddress("10.20.0.0/16");
        assertThat(address.get(request("10.20.0.2", "2001:db8::1")))
                .isEqualTo(address.get(request("10.20.0.2", "2001:0db8:0:0:0:0:0:1")));
    }

    private static MockHttpServletRequest request(String peer, String forwarded) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(peer);
        request.addHeader("X-Site-Client-IP", forwarded);
        return request;
    }
}
