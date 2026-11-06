package com.example.multichain;

import java.io.IOException;

import jakarta.servlet.http.HttpServletResponse;

final class SecurityResponses {

    private SecurityResponses() {
    }

    static void error(HttpServletResponse response, int status) throws IOException {
        String body = switch (status) {
            case 401 -> "{\"message\":\"请先登录，或检查用户名与密码\"}";
            case 403 -> "{\"message\":\"权限不足或请求验证失败\"}";
            case 429 -> "{\"message\":\"登录尝试过多，请稍后再试\"}";
            case 503 -> "{\"message\":\"登录服务暂不可用\"}";
            default -> throw new IllegalArgumentException("Unsupported security status: " + status);
        };
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write(body);
    }
}
