package com.clientum.signer.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

public class ApiKeyFilter extends OncePerRequestFilter {

  private final String expectedKey;

  public ApiKeyFilter(String expectedKey) {
    this.expectedKey = expectedKey == null ? "" : expectedKey.trim();
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    // Sólo proteger /api/**
    String path = request.getRequestURI();
    return path == null || !path.startsWith("/api/");
  }

  @Override
  protected void doFilterInternal(
      HttpServletRequest request,
      HttpServletResponse response,
      FilterChain filterChain) throws ServletException, IOException {

    // Si no hay clave configurada, no bloquear (modo “passthrough”)
    if (!StringUtils.hasText(expectedKey)) {
      filterChain.doFilter(request, response);
      return;
    }

    String provided = request.getHeader("X-Clientum-Api-Key");
    if (expectedKey.equals(provided)) {
      filterChain.doFilter(request, response);
    } else {
      response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      response.setContentType("application/json");
      response.getWriter().write("{\"error\":\"invalid_api_key\"}");
    }
  }
}
