package com.aegis.gateway.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidatorResult;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtTimestampValidator;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.net.URI;
import java.util.*;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http, JwtDecoder jwtDecoder) throws Exception {
        http
            .csrf(AbstractHttpConfigurer::disable)
            .cors(Customizer.withDefaults())
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/actuator/health/**", "/actuator/info", "/actuator/prometheus").permitAll()
                .requestMatchers(HttpMethod.OPTIONS, "/**").permitAll()
                .requestMatchers("/transfers/**", "/api/v1/transfers/**").hasRole("CUSTOMER")
                .requestMatchers(
                    "/customers/**", "/api/v1/customers/**",
                    "/accounts/**", "/api/v1/accounts/**",
                    "/beneficiaries/**", "/api/v1/beneficiaries/**",
                    "/transactions/**", "/api/v1/transactions/**"
                ).hasAnyRole("CUSTOMER", "SECURITY_ANALYST", "SECURITY_ADMIN")
                .requestMatchers("/security/**", "/api/v1/security/**").hasAnyRole("SECURITY_ANALYST", "SECURITY_ADMIN")
                .anyRequest().authenticated()
            )
            .oauth2ResourceServer(oauth2 -> oauth2
                .jwt(jwt -> jwt.decoder(jwtDecoder).jwtAuthenticationConverter(jwtAuthenticationConverter()))
                .authenticationEntryPoint((request, response, authException) -> {
                    response.setStatus(HttpStatus.UNAUTHORIZED.value());
                    response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
                    ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                        HttpStatus.UNAUTHORIZED,
                        authException != null ? authException.getMessage() : "Full authentication is required"
                    );
                    problem.setTitle("Unauthorized");
                    problem.setType(URI.create("https://aegis.dev/errors/unauthorized"));
                    objectMapper.writeValue(response.getOutputStream(), problem);
                })
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    response.setStatus(HttpStatus.FORBIDDEN.value());
                    response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
                    ProblemDetail problem = ProblemDetail.forStatusAndDetail(
                        HttpStatus.FORBIDDEN,
                        "Access is denied"
                    );
                    problem.setTitle("Forbidden");
                    problem.setType(URI.create("https://aegis.dev/errors/forbidden"));
                    objectMapper.writeValue(response.getOutputStream(), problem);
                })
            );

        return http.build();
    }

    @Bean
    public JwtDecoder jwtDecoder(@Value("${spring.security.oauth2.resourceserver.jwt.jwk-set-uri}") String jwkSetUri) {
        NimbusJwtDecoder jwtDecoder = NimbusJwtDecoder.withJwkSetUri(jwkSetUri).build();
        OAuth2TokenValidator<Jwt> withTimestamp = new JwtTimestampValidator();
        OAuth2TokenValidator<Jwt> issuerValidator = token -> {
            String issuer = token.getIssuer() != null ? token.getIssuer().toString() : "";
            if (issuer.endsWith("/realms/aegis-dev")) {
                return OAuth2TokenValidatorResult.success();
            }
            return OAuth2TokenValidatorResult.failure(new OAuth2Error("invalid_token", "Invalid issuer: " + issuer, null));
        };
        OAuth2TokenValidator<Jwt> delegatingValidator = new DelegatingOAuth2TokenValidator<>(withTimestamp, issuerValidator);
        jwtDecoder.setJwtValidator(delegatingValidator);
        return jwtDecoder;
    }

    @Bean
    public JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new KeycloakRoleConverter());
        return converter;
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        configuration.setAllowedOriginPatterns(List.of(
            "http://localhost:*",
            "http://127.0.0.1:*"
        ));
        configuration.setAllowedMethods(List.of("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"));
        configuration.setAllowedHeaders(List.of("*"));
        configuration.setExposedHeaders(List.of("X-Correlation-Id", "Location", "Idempotency-Key"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    private static class KeycloakRoleConverter implements Converter<Jwt, Collection<GrantedAuthority>> {
        @Override
        public Collection<GrantedAuthority> convert(Jwt jwt) {
            Set<GrantedAuthority> authorities = new HashSet<>();
            Map<String, Object> realmAccess = jwt.getClaim("realm_access");
            if (realmAccess != null && realmAccess.get("roles") instanceof Collection<?> roles) {
                for (Object role : roles) {
                    if (role instanceof String r && !r.isBlank()) {
                        authorities.add(new SimpleGrantedAuthority("ROLE_" + r));
                    }
                }
            }
            return authorities;
        }
    }
}
