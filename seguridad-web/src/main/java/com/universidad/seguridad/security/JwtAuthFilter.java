package com.universidad.seguridad.security;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Valida el header "Authorization: Bearer <token>" en CADA petición a /api/**.
 * Solo se registra dentro de apiFilterChain (ver SecurityConfig).
 */
@Component
public class JwtAuthFilter extends OncePerRequestFilter {

    private static final String PREFIJO = "Bearer ";

    private final JwtUtil jwtUtil;

    public JwtAuthFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        String header = request.getHeader("Authorization");

        if (header != null && header.startsWith(PREFIJO)) {
            String token = header.substring(PREFIJO.length());

            if (jwtUtil.esValido(token)) {
                String email = jwtUtil.extraerEmail(token);
                String rol = jwtUtil.extraerRol(token);

                var authToken = new UsernamePasswordAuthenticationToken(
                        email, null, List.of(new SimpleGrantedAuthority(rol)));
                // Se puebla el SecurityContext a mano: no hay sesión de la que Spring
                // Security pueda recuperar al usuario en la siguiente petición, por eso
                // este filtro corre en CADA petición. Los datos salen del propio token
                // firmado, sin consultar la base de datos.
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
            // Si el token no es válido, simplemente no se autentica: authorizeHttpRequests
            // de apiFilterChain decide y responde 401 si la ruta lo exigía.
        }

        chain.doFilter(request, response);
    }
}
