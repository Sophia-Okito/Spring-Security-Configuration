package com.example.springsecurity.configurations;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.MDC;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class AppEnvironmentFilter extends OncePerRequestFilter {
    private static final String ENVIRONMENT_MDC_KEY = "environment";

    @Value("${app.environment:dev}")
    private String environment;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            MDC.put(ENVIRONMENT_MDC_KEY, environment);
            filterChain.doFilter(request, response);
        } finally {
            MDC.remove(ENVIRONMENT_MDC_KEY);
        }
    }
}
