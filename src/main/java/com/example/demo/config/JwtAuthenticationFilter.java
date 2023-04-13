package com.example.demo.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

// fires everytime users makes a request
@Component
// create a constructor using any final field
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        // extract header from request body
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        // Beare token starts with Bearer 
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            // pass to the next filter
            filterChain.doFilter(request, response);
            return;
        }
        // count from after Bearer
        jwt = authHeader.substring(7);
/*
        userEmail = jwtService.extractUsername(jwt);
*/

    }
}
