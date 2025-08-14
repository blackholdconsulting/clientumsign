package com.clientum.signer.security;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class ApiKeyFilterConfig {

  // Default vacío para no romper el arranque si falta la env var
  @Value("${SIGNER_API_KEY:}")
  private String apiKey;

  @Bean
  public FilterRegistrationBean<ApiKeyFilter> apiKeyFilterRegistration() {
    ApiKeyFilter filter = new ApiKeyFilter(apiKey);
    FilterRegistrationBean<ApiKeyFilter> reg = new FilterRegistrationBean<>();
    reg.setFilter(filter);
    reg.addUrlPatterns("/api/*"); // sólo protege rutas /api/**
    reg.setOrder(1);
    return reg;
  }
}
