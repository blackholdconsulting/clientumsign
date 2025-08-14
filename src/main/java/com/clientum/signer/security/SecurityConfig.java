package com.clientum.signer.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

  @Bean
  SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
    http
      .csrf(AbstractHttpConfigurer::disable)
      .cors(Customizer.withDefaults())
      .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
      .httpBasic(AbstractHttpConfigurer::disable)
      .formLogin(AbstractHttpConfigurer::disable) // <- SIN formulario de login
      .authorizeHttpRequests(auth -> auth
        .requestMatchers(
            "/", "/login",                        // <- permitimos para redirigir/ocultar
            "/actuator/health", "/actuator/info",
            "/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**",
            "/api/sign/**"
        ).permitAll()
        .anyRequest().authenticated()
      )
      .exceptionHandling(e -> e
        .authenticationEntryPoint((req, res, ex) ->
          res.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized"))
      );

    return http.build();
  }
}
