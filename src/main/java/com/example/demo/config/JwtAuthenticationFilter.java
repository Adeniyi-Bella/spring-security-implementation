package com.example.demo.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.security.authentication.CachingUserDetailsService;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;


import java.io.IOException;

// fires everytime users makes a request
@Component
// create a constructor using any final field
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    // from userdetails class
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {
        // extract header
        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;
        // Bearer token starts with Bearer
        if (authHeader == null ||!authHeader.startsWith("Bearer ")) {
            // pass to the next filter
            filterChain.doFilter(request, response);
            return;
        }
        // count from after Bearer
        jwt = authHeader.substring(7);
        // create a service class that extracts the email from the request body
        userEmail = jwtService.extractUsername(jwt);
    // check if user is available or user has been validated once before expiration
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // already implemented in Application.java which matches the email in our DB
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            /*var isTokenValid = tokenRepository.findByToken(jwt)
                    .map(t -> !t.isExpired() && !t.isRevoked())
                    .orElse(false);*/
            if (jwtService.isTokenValid(jwt, userDetails)) {
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
    }
}
