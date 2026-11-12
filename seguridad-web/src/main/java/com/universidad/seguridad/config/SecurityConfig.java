package com.universidad.seguridad.config;

import com.universidad.seguridad.security.JwtAuthFilter;
import com.universidad.seguridad.security.UsuarioDetailsService;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // activa @PreAuthorize en los servicios
public class SecurityConfig {

    // BCrypt con factor de costo 12 (2^12 rondas): los hashes empiezan por $2a$12$
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder(12);
    }

    @Bean
    public DaoAuthenticationProvider authProvider(UsuarioDetailsService uds, PasswordEncoder pe) {
        DaoAuthenticationProvider p = new DaoAuthenticationProvider();
        p.setUserDetailsService(uds);
        p.setPasswordEncoder(pe);
        return p;
    }

    // Se expone el AuthenticationManager (el mismo que usa el form-login)
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager();
    }

    // Cadena de filtros para la API REST — stateless con JWT (Parte 2).
    // @Order(1): se evalúa ANTES que webFilterChain (@Order(2)); lo más específico
    // primero, como recomienda Spring Security para varias SecurityFilterChain.
    @Bean
    @Order(1)
    public SecurityFilterChain apiFilterChain(HttpSecurity http, JwtAuthFilter jwtAuthFilter) throws Exception {
        http
            .securityMatcher("/api/**") // esta cadena SOLO aplica a /api/**
            // Correcto SOLO aquí: no hay cookie de sesión que un sitio malicioso pueda
            // aprovechar; el token viaja en un header que un formulario cross-site no
            // puede fijar por sí solo
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/login").permitAll()
                .requestMatchers("/api/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            // Sin form-login ni httpBasic, una petición sin token recibiría 403 por defecto;
            // se responde 401 Unauthorized, el código correcto para "no autenticado"
            .exceptionHandling(ex -> ex
                .authenticationEntryPoint(new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)))
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // Spring Boot registra automáticamente todo bean Filter en el contenedor para
    // TODAS las rutas. Se desactiva ese registro global: JwtAuthFilter debe correr
    // solo dentro de apiFilterChain, así no interfiere con las vistas de sesión.
    @Bean
    public FilterRegistrationBean<JwtAuthFilter> desactivarRegistroGlobal(JwtAuthFilter filtro) {
        FilterRegistrationBean<JwtAuthFilter> registro = new FilterRegistrationBean<>(filtro);
        registro.setEnabled(false);
        return registro;
    }

    // Cadena de filtros para las vistas web con Thymeleaf — basada en sesión.
    // @Order(2): se evalúa después de la cadena de /api/** (Parte 2), que tiene
    // @Order(1). Sin @Order explícito, Spring Security no garantiza cuál cadena
    // evalúa primero cuando hay más de un SecurityFilterChain.
    @Bean
    @Order(2)
    public SecurityFilterChain webFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/**") // todo lo que no atienda una cadena de mayor prioridad
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/", "/login", "/registro", "/css/**", "/js/**", "/error").permitAll()
                .requestMatchers("/admin/**").hasRole("ADMIN")
                .anyRequest().authenticated()
            )
            .formLogin(form -> form
                .loginPage("/login")
                .loginProcessingUrl("/login")
                .defaultSuccessUrl("/dashboard", true)
                .failureUrl("/login?error=true")
                .permitAll()
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login?logout")
                .invalidateHttpSession(true)
                .deleteCookies("JSESSIONID")
                .permitAll()
            )
            .exceptionHandling(ex -> ex.accessDeniedPage("/acceso-denegado"));
            // CSRF queda ACTIVO (comportamiento por defecto de Spring Security):
            // esta cadena sirve formularios Thymeleaf con cookie de sesión,
            // el escenario exacto contra el que protege CSRF.
        return http.build();
    }
}
