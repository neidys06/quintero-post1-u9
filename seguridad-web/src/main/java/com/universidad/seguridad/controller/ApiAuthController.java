package com.universidad.seguridad.controller;

import com.universidad.seguridad.security.JwtUtil;
import java.util.Map;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** POST /api/auth/login — valida credenciales y emite un JWT. */
@RestController
@RequestMapping("/api/auth")
public class ApiAuthController {

    private final AuthenticationManager authManager;
    private final JwtUtil jwtUtil;

    public ApiAuthController(AuthenticationManager authManager, JwtUtil jwtUtil) {
        this.authManager = authManager;
        this.jwtUtil = jwtUtil;
    }

    public record LoginRequest(String email, String contrasenia) {}
    public record LoginResponse(String token, String email, String rol) {}

    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest req) {
        try {
            // Reutiliza el MISMO AuthenticationManager/UserDetailsService/BCrypt de la
            // Parte 1: las credenciales se validan igual; solo cambia lo que se
            // devuelve (un token en vez de una cookie de sesión).
            Authentication auth = authManager.authenticate(
                    new UsernamePasswordAuthenticationToken(req.email(), req.contrasenia()));
            String rol = auth.getAuthorities().iterator().next().getAuthority();
            String token = jwtUtil.generarToken(auth.getName(), rol);
            return ResponseEntity.ok(new LoginResponse(token, auth.getName(), rol));
        } catch (AuthenticationException e) {
            // Credenciales inválidas: 401 sin token (mensaje genérico, no revela si el correo existe)
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(Map.of("error", "Credenciales inválidas"));
        }
    }
}
