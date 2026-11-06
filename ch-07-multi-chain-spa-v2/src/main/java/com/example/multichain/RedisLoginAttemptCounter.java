package com.example.multichain;

import java.util.List;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;

final class RedisLoginAttemptCounter implements LoginAttemptCounter {

    private static final DefaultRedisScript<Long> INCREMENT = new DefaultRedisScript<>("""
            local n = redis.call('INCR', KEYS[1])
            if n == 1 then
                redis.call('EXPIRE', KEYS[1], 900)
            end
            return n
            """, Long.class);

    private final StringRedisTemplate redis;

    RedisLoginAttemptCounter(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public Long increment(String clientIp) {
        return this.redis.execute(INCREMENT, List.of("site:login:" + clientIp));
    }
}
