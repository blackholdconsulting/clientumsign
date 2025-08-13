package com.clientum.signer.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;

@Component
public class ApiKeyFilter extends OncePerRequestFilter {

  private final Environment env;

  public ApiKeyFilter(Environment env) {
    this.env = env;
  }

  @Override
  protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
      throws ServletException, IOException {

    // Permite preflight CORS
    if ("OPTIONS".equalsIgnoreCase(req.getMethod())) {
      chain.doFilter(req, res);
      return;
    }

    // Endpoints públicos
    String path = req.getRequestURI();
    if (path.startsWith("/actuator/health") || path.startsWith("/v3/api-docs") ||
        path.startsWith("/swagger-ui") || path.equals("/swagger-ui.html")) {
      chain.doFilter(req, res);
      return;
    }

    String headerName = env.getProperty("SIGN_API_KEY_HEADER", "x-api-key");
    String apiKey = req.getHeader(headerName);
    String configured = env.getProperty("SIGN_API_KEYS", ""); // coma-separado
    Set<String> allowed = Arrays.stream(configured.split(","))
        .map(String::trim).filter(s -> !s.isEmpty()).collect(Collectors.toSet());

    boolean required = Boolean.parseBoolean(env.getProperty("SIGN_REQUIRE_API_KEY", "true"));

    if (!required) {
      chain.doFilter(req, res);
      return;
    }

    if (apiKey == null || !allowed.contains(apiKey)) {
      res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
      res.setContentType("application/json");
      res.getWriter().write("{\"error\":\"API key inválida o ausente\"}");
      return;
    }

    chain.doFilter(req, res);
  }
}
