package org.example.config;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletResponse;
import org.example.repository.ReaderRepository;
import org.example.service.JwtService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.oauth2.server.resource.web.DefaultBearerTokenResolver;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;

import java.io.IOException;
import java.util.List;

@Configuration
@EnableMethodSecurity
public class SecurityConfig {
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, JwtService tokens, ReaderRepository readers) throws Exception {
        var authEndpoints = new AntPathRequestMatcher("/auth/**");
        var bearerTokens = new DefaultBearerTokenResolver();
        AuthenticationEntryPoint unauthorized = (request, response, exception) -> {
            response.setHeader("WWW-Authenticate", "Bearer");
            error(response, 401, "Authentication required or invalid credentials");
        };
        return http
                .authorizeHttpRequests(auth -> auth
                        .dispatcherTypeMatchers(DispatcherType.ERROR).permitAll()
                        .requestMatchers(HttpMethod.GET, "/swagger-ui/**", "/swagger-ui.html", "/v3/api-docs/**").permitAll()
                        .requestMatchers(HttpMethod.POST, "/auth/login", "/auth/register", "/auth/refresh").permitAll()
                        .requestMatchers(HttpMethod.GET, "/api/books/**", "/api/categories/**",
                                "/api/readers/**", "/api/loans/**").authenticated()
                        .requestMatchers(HttpMethod.POST, "/api/business/extend",
                                "/api/business/pay-fine").authenticated()
                        .requestMatchers("/api/**").hasRole("LIBRARIAN")
                        .anyRequest().denyAll())
                .oauth2ResourceServer(oauth -> oauth
                        .bearerTokenResolver(request -> {
                            // Публичные операции работают только с данными из JSON.
                            return authEndpoints.matches(request) ? null : bearerTokens.resolve(request);
                        })
                        .authenticationEntryPoint(unauthorized)
                        .jwt(jwt -> jwt.decoder(tokens::validateAccess).jwtAuthenticationConverter(token -> {
                            var reader = readers.findById(tokens.readerId(token))
                                    .filter(r -> Boolean.TRUE.equals(r.getActive()) && token.getSubject().equals(r.getEmail()))
                                    .orElseThrow(() -> new InvalidBearerTokenException("Invalid account"));
                            return new JwtAuthenticationToken(token,
                                    List.of(new SimpleGrantedAuthority("ROLE_" + reader.getRole().name())));
                        })))
                .exceptionHandling(errors -> errors.authenticationEntryPoint(unauthorized)
                        .accessDeniedHandler((request, response, exception) ->
                                error(response, 403, "Access denied")))
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .csrf(csrf -> csrf.disable()) // Токены принимаются из заголовка, а не из cookie.
                .requestCache(cache -> cache.disable())
                .logout(logout -> logout.disable())
                .build();
    }

    private static void error(HttpServletResponse response, int status, String message) throws IOException {
        response.setStatus(status);
        response.setContentType("application/json;charset=UTF-8");
        response.getWriter().write("{\"status\":" + status + ",\"message\":\"" + message + "\"}");
    }
}
