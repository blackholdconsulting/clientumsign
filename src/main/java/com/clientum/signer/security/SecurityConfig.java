package com.clientum.signer.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http
      .csrf(csrf -> csrf.disable())
      .cors(Customizer.withDefaults())
      .headers(h -> h.frameOptions(f -> f.sameOrigin())) // útil para swagger-ui en algunos hosts
      .authorizeHttpRequests(auth -> auth
        .requestMatchers(
          "/actuator/**",
          "/swagger-ui/**", "/swagger-ui.html",
          "/v3/api-docs/**",
          "/api/**",         // dejamos pasar; el filtro de API Key controla acceso
          "/error"
        ).permitAll()
        .anyRequest().denyAll()
      )
      .formLogin(f -> f.disable())
      .httpBasic(b -> b.disable());

    return http.build();
  }
}
