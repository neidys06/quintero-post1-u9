package com.universidad.seguridad.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import java.nio.charset.StandardCharsets;
import java.util.Date;
import javax.crypto.SecretKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

/** Genera y valida tokens JWT firmados con HMAC-SHA256 y con expiración. */
@Component
public class JwtUtil {

    private final SecretKey clave;
    private final long expiracionMs;

    // La clave viene de application.properties → variable de entorno JWT_SECRET.
    // Nunca se escribe en el código: con ella cualquiera podría firmar tokens válidos.
    public JwtUtil(@Value("${jwt.secret}") String secreto,
                   @Value("${jwt.expiracion-ms:3600000}") long expiracionMs) {
        if (secreto.getBytes(StandardCharsets.UTF_8).length < 32) {
            throw new IllegalStateException("jwt.secret debe tener al menos 32 bytes para HS256");
        }
        this.clave = Keys.hmacShaKeyFor(secreto.getBytes(StandardCharsets.UTF_8));
        this.expiracionMs = expiracionMs; // 1 hora por defecto
    }

    public String generarToken(String email, String rol) {
        Date ahora = new Date();
        return Jwts.builder()
                .subject(email)
                .claim("rol", rol)
                .issuedAt(ahora)
                .expiration(new Date(ahora.getTime() + expiracionMs))
                .signWith(clave)
                .compact();
    }

    public String extraerEmail(String token) {
        return parsearClaims(token).getSubject();
    }

    public String extraerRol(String token) {
        return parsearClaims(token).get("rol", String.class);
    }

    public boolean esValido(String token) {
        try {
            parsearClaims(token); // lanza excepción si la firma o la expiración no son válidas
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false; // firma inválida, token expirado o malformado
        }
    }

    private Claims parsearClaims(String token) {
        return Jwts.parser()
                .verifyWith(clave)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }
}
