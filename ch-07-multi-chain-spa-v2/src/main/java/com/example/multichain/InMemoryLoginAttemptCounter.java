package com.example.multichain;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;

final class InMemoryLoginAttemptCounter implements LoginAttemptCounter {

    private static final Duration WINDOW = Duration.ofMinutes(15);

    private final ConcurrentHashMap<String, Window> attempts = new ConcurrentHashMap<>();

    private final Clock clock;

    InMemoryLoginAttemptCounter(Clock clock) {
        this.clock = clock;
    }

    @Override
    public Long increment(String clientIp) {
        Instant now = this.clock.instant();
        Window current = this.attempts.compute(clientIp, (key, previous) -> {
            if (previous == null || !now.isBefore(previous.expiresAt())) {
                return new Window(1, now.plus(WINDOW));
            }
            return new Window(previous.count() + 1, previous.expiresAt());
        });
        return current.count();
    }

    void clear() {
        this.attempts.clear();
    }

    private record Window(long count, Instant expiresAt) {
    }
}
