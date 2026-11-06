package com.example.multichain;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class InMemoryLoginAttemptCounterTest {

    @Test
    void expiryStartsAtFirstAttemptAndDoesNotSlideOnLaterAttempts() {
        MutableClock clock = new MutableClock();
        InMemoryLoginAttemptCounter counter = new InMemoryLoginAttemptCounter(clock);
        assertThat(counter.increment("192.0.2.1")).isEqualTo(1);
        clock.seconds = 899;
        assertThat(counter.increment("192.0.2.1")).isEqualTo(2);
        clock.seconds = 900;
        assertThat(counter.increment("192.0.2.1")).isEqualTo(1);
    }

    @Test
    void differentAddressesHaveIndependentCounters() {
        InMemoryLoginAttemptCounter counter = new InMemoryLoginAttemptCounter(Clock.systemUTC());
        assertThat(counter.increment("192.0.2.1")).isEqualTo(1);
        assertThat(counter.increment("192.0.2.1")).isEqualTo(2);
        assertThat(counter.increment("192.0.2.2")).isEqualTo(1);
    }

    private static final class MutableClock extends Clock {

        private long seconds;

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return Instant.EPOCH.plusSeconds(this.seconds);
        }
    }
}
