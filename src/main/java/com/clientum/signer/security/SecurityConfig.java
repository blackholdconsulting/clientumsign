package com.clientum.signer.security;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Value("${SIGNER_API_KEY:}")
    private String signerApiKey;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
            // API stateless
            .csrf(AbstractHttpConfigurer::disable)
            .cors(Customizer.withDefaults())
            .sessionManagement(sm -> sm.sessionCreationPolicy(SessionCreationPolicy.STATELESS))

            // Desactivar login form, http basic y logout -> así desaparece /login
            .formLogin(AbstractHttpConfigurer::disable)
            .httpBasic(AbstractHttpConfigurer::disable)
            .logout(AbstractHttpConfigurer::disable)

            // Respuesta 401 JSON cuando falta autenticación
            .exceptionHandling(ex -> ex.authenticationEntryPoint((req, res, e) -> {
                res.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                res.setContentType("application/json");
                res.getWriter().write("{\"error\":\"unauthorized\"}");
            }))

            // Autorización
            .authorizeHttpRequests(auth -> auth
                // Health y Swagger abiertos
                .requestMatchers(
                    "/actuator/health/**",
                    "/v3/api-docs/**",
                    "/swagger-ui/**",
                    "/swagger-ui.html"
                ).permitAll()

                // Solo aceptamos POST en /api/sign/** con API Key
                .requestMatchers(HttpMethod.POST, "/api/sign/**").authenticated()

                // Todo lo demás: 404/403 (mejor denyAll)
                .anyRequest().denyAll()
            );

        // Filtro de API Key antes del filtro de usuario/clave
        http.addFilterBefore(new ApiKeyFilter("X-API-KEY", signerApiKey),
                UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
