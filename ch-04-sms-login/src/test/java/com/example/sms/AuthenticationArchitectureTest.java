package com.example.sms;

import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsPasswordService;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class AuthenticationArchitectureTest {

    private static final String PHONE = "13800138000";

    @Test
    void managerPollsProvidersAndErasesCredentialsAfterSuccess() {
        SmsLoginApplication.SmsToken request =
                SmsLoginApplication.SmsToken.unauthenticated(PHONE, "654321");
        assertFalse(request.isAuthenticated());
        assertEquals("654321", request.getCredentials());

        AtomicInteger secondProviderCalls = new AtomicInteger();
        AuthenticationProvider first = provider(authentication -> {
            throw new BadCredentialsException("First provider cannot verify this code");
        });
        AuthenticationProvider second = provider(authentication -> {
            secondProviderCalls.incrementAndGet();
            Authentication result = UsernamePasswordAuthenticationToken.authenticated(
                    PHONE, "654321", demoUser().getAuthorities());
            assertEquals("654321", result.getCredentials());
            return result;
        });

        Authentication result = new ProviderManager(List.of(first, second)).authenticate(request);
        assertEquals(1, secondProviderCalls.get());
        assertTrue(result.isAuthenticated());
        assertEquals(PHONE, result.getName());
        assertNull(result.getCredentials());
        assertEquals("654321", request.getCredentials());
    }

    @Test
    void managerStopsOnDisabledSmsAccountBeforeTryingSuccessfulFallback() {
        SmsLoginApplication.SmsCodes codes =
                new SmsLoginApplication.SmsCodes(PHONE, "654321");
        UserDetails disabled = User.withUserDetails(demoUser()).disabled(true).build();
        AuthenticationProvider sms = new SmsLoginApplication.SmsProvider(
                username -> disabled, codes);
        AtomicInteger fallbackCalls = new AtomicInteger();
        AuthenticationProvider fallback = provider(authentication -> {
            fallbackCalls.incrementAndGet();
            return SmsLoginApplication.SmsToken.authenticated(demoUser());
        });
        ProviderManager manager = new ProviderManager(List.of(sms, fallback));

        assertThrows(DisabledException.class, () -> manager.authenticate(
                SmsLoginApplication.SmsToken.unauthenticated(PHONE, "654321")));
        assertEquals(0, fallbackCalls.get());
        assertFalse(codes.consume(PHONE, "654321"));
    }

    @Test
    void managerTriesParentWhenChildHasOnlyOrdinaryAuthenticationFailure() {
        AtomicInteger parentCalls = new AtomicInteger();
        AuthenticationProvider child = provider(authentication -> {
            throw new BadCredentialsException("Child cannot verify this code");
        });
        ProviderManager manager = new ProviderManager(List.of(child), authentication -> {
            parentCalls.incrementAndGet();
            return SmsLoginApplication.SmsToken.authenticated(demoUser());
        });

        Authentication result = manager.authenticate(
                SmsLoginApplication.SmsToken.unauthenticated(PHONE, "654321"));
        assertEquals(1, parentCalls.get());
        assertTrue(result.isAuthenticated());
        assertNull(result.getCredentials());
    }

    @Test
    void daoProviderUpgradesLegacyHashOnlyWhenPasswordServiceWritesItBack() {
        PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        AtomicReference<UserDetails> stored = new AtomicReference<>(User.withUsername("alice")
                .password("{noop}correct-horse").roles("USER").build());
        UserDetailsService users = username -> stored.get();

        DaoAuthenticationProvider withoutWrites = new DaoAuthenticationProvider(users);
        withoutWrites.setPasswordEncoder(encoder);
        // 仓库直接返回共享的可变 UserDetails；只把用户名放进认证结果，避免擦除仓库密码。
        withoutWrites.setForcePrincipalAsString(true);
        Authentication first = new ProviderManager(withoutWrites).authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated("alice", "correct-horse"));
        assertTrue(first.isAuthenticated());
        assertNull(first.getCredentials());
        assertEquals("{noop}correct-horse", stored.get().getPassword());

        AtomicInteger writes = new AtomicInteger();
        UserDetailsPasswordService passwordService = (user, newPassword) -> {
            writes.incrementAndGet();
            UserDetails updated = User.withUserDetails(user).password(newPassword).build();
            stored.set(updated);
            return updated;
        };
        DaoAuthenticationProvider withWrites = new DaoAuthenticationProvider(users);
        withWrites.setPasswordEncoder(encoder);
        withWrites.setUserDetailsPasswordService(passwordService);
        withWrites.setForcePrincipalAsString(true);

        Authentication second = new ProviderManager(withWrites).authenticate(
                UsernamePasswordAuthenticationToken.unauthenticated("alice", "correct-horse"));
        assertTrue(second.isAuthenticated());
        assertEquals(1, writes.get());
        assertTrue(stored.get().getPassword().startsWith("{bcrypt}"));
        assertTrue(encoder.matches("correct-horse", stored.get().getPassword()));
        assertNull(second.getCredentials());
        assertNotNull(second.getPrincipal());
        assertThrows(IllegalArgumentException.class,
                () -> encoder.matches("correct-horse", "unprefixed-hash"));
    }

    private static UserDetails demoUser() {
        return User.withUsername(PHONE).password("{noop}unused").roles("USER").build();
    }

    private static AuthenticationProvider provider(AuthenticationAttempt attempt) {
        return new AuthenticationProvider() {
            @Override
            public Authentication authenticate(Authentication authentication) {
                return attempt.authenticate(authentication);
            }

            @Override
            public boolean supports(Class<?> type) {
                return SmsLoginApplication.SmsToken.class.isAssignableFrom(type);
            }
        };
    }

    @FunctionalInterface
    private interface AuthenticationAttempt {
        Authentication authenticate(Authentication authentication);
    }
}
