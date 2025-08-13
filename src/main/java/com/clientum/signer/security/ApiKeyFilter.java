package com.clientum.signer.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class ApiKeyFilter extends OncePerRequestFilter {
    private final String headerName;
    private final String expectedValue;

    public ApiKeyFilter(String headerName, String expectedValue) {
        this.headerName = headerName;
        this.expectedValue = expectedValue;
    }

    @Override
    protected void doFilterInternal(
            HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {

        String apiKey = request.getHeader(headerName);

        if (apiKey != null && apiKey.equals(expectedValue)) {
            // Autenticación simple basada en API Key
            Authentication auth = new AbstractAuthenticationToken(
                    List.of(new SimpleGrantedAuthority("ROLE_API"))) {
                @Override public Object getCredentials() { return apiKey; }
                @Override public Object getPrincipal() { return "api-key"; }
                @Override public boolean isAuthenticated() { return true; }
            };
            // Continuar con contexto autenticado
            // (SecurityContextHolder no es necesario con Spring Security 6 si solo validamos y dejamos pasar)
        } else if (requiresAuth(request)) {
            // Falta/incorrecta -> 401
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType("application/json");
            response.getWriter().write("{\"error\":\"invalid or missing X-API-KEY\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private boolean requiresAuth(HttpServletRequest request) {
        String path = request.getRequestURI();
        // Solo protegemos /api/** (el resto está denyAll/permitAll en SecurityConfig)
        return path.startsWith("/api/");
    }
}
