package com.Arka.MSApiGateway.config.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class JwtUtil {

    private final SecretKey signingKey;

    public JwtUtil(@Value("${jwt.secret-key}") String secretKey,
                   @Value("${jwt.expiration}") long expirationTime) {

        this.signingKey = Keys.hmacShaKeyFor(secretKey.getBytes(StandardCharsets.UTF_8));
    }
    /**
     * Valida el token JWT.
     */
    public boolean validateToken(String token) {
        try {

            Jwts.parser()
                    .verifyWith(signingKey)
                    .build()
                    .parseSignedClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            return false;
        } catch (SignatureException | MalformedJwtException | UnsupportedJwtException | IllegalArgumentException e) {
            return false;
        }
    }

    /**
     * Obtiene el email del usuario desde el token JWT.
     */
    public String getEmailFromToken(String token) {
        return Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload()
                .getSubject(); // El Subject es el email del usuario en tu implementación
    }

    /**
     * Obtiene las autoridades (roles/permisos) del usuario desde el token JWT.
     */
    public List<GrantedAuthority> getAuthoritiesFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        String authoritiesString = claims.get("authorities", String.class);

        if (authoritiesString == null || authoritiesString.isEmpty()) {
            return List.of();
        }

        return Arrays.stream(authoritiesString.split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());
    }

    /**
     * Obtiene el ID del usuario desde el token JWT.
     */
    public Long getUserIdFromToken(String token) {
        Claims claims = Jwts.parser()
                .verifyWith(signingKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();

        // El ID puede venir como Integer o Long según tu backend
        Object idObj = claims.get("id");

        if (idObj instanceof Integer) {
            return ((Integer) idObj).longValue();
        } else if (idObj instanceof Long) {
            return (Long) idObj;
        }

        return null;
    }
}
    /*
1. Usuario envía request con header:
Authorization: Bearer eyJhbGc...

        2. AuthenticationFilter extrae el token y llama:
        jwtUtil.validateToken(token)  → ¿Es válido? → ✅ Sí

3. Si es válido, extrae información:
        jwtUtil.getEmailFromToken(token)  → "usuario@ejemplo.com"
        jwtUtil.getAuthoritiesFromToken(token)  → ["productos:crear", "productos:visualizar"]

        4. Añade headers al request para el microservicio:
X-Auth-Email: usuario@ejemplo.com
X-Auth-Roles: productos:crear,productos:visualizar

5. AuthorizationFilter verifica si el usuario tiene el permiso requerido
   ¿Tiene "productos:crear"? → ✅ Sí → Permite el acceso

   */