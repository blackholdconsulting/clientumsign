package com.clientum.signer.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

public class ApiKeyFilter extends OncePerRequestFilter {

  private final String expectedKey;

  // Rutas que nunca se filtran (públicas)
  private final List<AntPathRequestMatcher> publicMatchers = List.of(
      new AntPathRequestMatcher("/actuator/**"),
      new AntPathRequestMatcher("/v3/api-docs/**"),
      new AntPathRequestMatcher("/swagger-ui/**"),
      new AntPathRequestMatcher("/swagger-ui.html")
  );

  public ApiKeyFilter(String expectedKey) {
    this.expectedKey = expectedKey;
  }

  @Override
  protected boolean shouldNotFilter(HttpServletRequest request) {
    // No filtrar si coincide con rutas públicas
    for (var m : publicMatchers) {
      if (m.matches(request)) return true;
    }
    // Solo filtrar cuando se accede a /api/sign/**
    return !new AntPathRequestMatcher("/api/sign/**").matches(request);
  }

  @Override
  protected void doFilterInternal(HttpServletRequest request,
                                  HttpServletResponse response,
                                  FilterChain filterChain) throws ServletException, IOException {

    // Intenta por X-API-Key
    String key = request.getHeader("X-API-Key");

    // Si no vino, intenta con Authorization: Bearer <token>
    if (key == null || key.isBlank()) {
      String auth = request.getHeader("Authorization");
      if (auth != null && auth.startsWith("Bearer ")) {
        key = auth.substring("Bearer ".length()).trim();
      }
    }

    if (key != null && !key.isBlank() && key.equals(expectedKey)) {
      // Autenticación "ficticia" para pasar el security chain
      var authToken = new UsernamePasswordAuthenticationToken("api-key-user", null, List.of());
      SecurityContextHolder.getContext().setAuthentication(authToken);
      filterChain.doFilter(request, response);
      return;
    }

    // 401 si la API key es inválida o ausente
    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
    response.setContentType("application/json");
    response.getWriter().write("{\"error\":\"invalid_api_key\"}");
  }
}
