package com.example.session;

import java.util.Map;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.security.config.Customizer;

@SpringBootApplication
public class SessionDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SessionDemoApplication.class, args);
    }

    @Bean
    SecurityFilterChain security(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(auth -> auth.anyRequest().authenticated());
        http.formLogin(Customizer.withDefaults());
        http.sessionManagement(session -> {
            session.sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED);
            session.sessionFixation(fixation -> fixation.changeSessionId());
            session.maximumSessions(1).maxSessionsPreventsLogin(true);
        });
        http.logout(Customizer.withDefaults());
        return http.build();
    }

    @Bean
    HttpSessionEventPublisher sessionEvents() {
        return new HttpSessionEventPublisher();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }

    @Bean
    UserDetailsService users(PasswordEncoder encoder,
                             @Value("${demo.password}") String password) {
        return new InMemoryUserDetailsManager(User.withUsername("zhouzhou")
                .password(encoder.encode(password)).roles("USER").build());
    }

    @RestController
    static class WhoAmI {
        @GetMapping("/me")
        Map<String, String> me(Authentication authentication) {
            return Map.of("name", authentication.getName());
        }
    }
}