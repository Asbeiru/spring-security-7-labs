package com.example.authorization;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;

@SpringBootApplication
@EnableMethodSecurity
public class AuthorizationDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(AuthorizationDemoApplication.class, args);
    }
}
