package com.example.multichain;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.List;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.web.util.matcher.IpAddressMatcher;

final class ClientAddress {

    private final List<IpAddressMatcher> trustedProxies;

    ClientAddress(String cidrs) {
        this.trustedProxies = Arrays.stream(cidrs.split(","))
                .map(String::strip)
                .filter(value -> !value.isEmpty())
                .map(IpAddressMatcher::new)
                .toList();
    }

    String get(HttpServletRequest request) {
        if (this.trustedProxies.stream().anyMatch(proxy -> proxy.matches(request))) {
            String address = normalizeLiteral(request.getHeader("X-Site-Client-IP"));
            if (address != null) {
                return address;
            }
        }
        return request.getRemoteAddr();
    }

    private static String normalizeLiteral(String value) {
        if (value == null) {
            return null;
        }
        if (value.contains(":")) {
            // 只把含冒号的地址字面量交给 IPv6 解析器，不解析任意主机名。
            if (!value.matches("[0-9a-fA-F:.]{2,45}")) {
                return null;
            }
            try {
                return InetAddress.getByName(value).getHostAddress();
            }
            catch (UnknownHostException exception) {
                return null;
            }
        }
        String[] parts = value.split("\\.", -1);
        if (parts.length != 4) {
            return null;
        }
        for (String part : parts) {
            if (!part.matches("0|[1-9][0-9]{0,2}") || Integer.parseInt(part) > 255) {
                return null;
            }
        }
        return value;
    }
}
