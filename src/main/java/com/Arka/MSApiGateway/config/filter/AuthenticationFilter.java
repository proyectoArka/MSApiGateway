package com.Arka.MSApiGateway.config.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Collectors;
import com.Arka.MSApiGateway.exception.ExpiredTokenException;
import com.Arka.MSApiGateway.exception.InvalidTokenException;
import com.Arka.MSApiGateway.dto.ErrorDto;
import com.Arka.MSApiGateway.exception.MissingJwtException;

@Component
public class AuthenticationFilter implements GlobalFilter, Ordered {

    private final JwtUtil jwtUtil;

    private static final List<String> openApiEndpoints = List.of(
            "/api/v1/gateway/auth/login",
            "/api/v1/gateway/auth/createclient",
            "/api/v1/gateway/auth/refresh",
            "/api/v1/gateway/productos/listar",
            "/api/v1/gateway/productos/buscar"

    );

    public AuthenticationFilter(JwtUtil jwtUtil) {
        this.jwtUtil = jwtUtil;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        String path = exchange.getRequest().getURI().getPath();

        // PASO 1: Verificar si es una ruta pública
        if (openApiEndpoints.stream().anyMatch(path::contains)) {
            return chain.filter(exchange);
        }

        // PASO 2: Validar el JWT en las demás rutas
        final String authHeader = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

        // Verificar si el encabezado de autorización está presente y tiene el formato correcto
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            // Lanzamos excepción que contiene el mensaje — así el mensaje se guarda en la excepción y no en la lógica del filtro
            try {
                throw new MissingJwtException();
            } catch (MissingJwtException ex) {
                return this.onError(exchange, ex.getMessage(), HttpStatus.UNAUTHORIZED);
            }
        }

        // Extraer el token JWT del encabezado
        String jwt = authHeader.substring(7);

        try {
            // Validar el token JWT (lanza excepción si inválido/expirado)
            jwtUtil.validateToken(jwt);

            // Modificar la solicitud para agregar los encabezados personalizados
            return chain.filter(this.mutateRequest(exchange, jwt));
        } catch (ExpiredTokenException e) {
            return this.onError(exchange, e.getMessage(), HttpStatus.UNAUTHORIZED);
        } catch (InvalidTokenException e) {
            return this.onError(exchange, e.getMessage(), HttpStatus.UNAUTHORIZED);
        } catch (MissingJwtException e) {
            return this.onError(exchange, e.getMessage(), HttpStatus.UNAUTHORIZED);
        }
    }

    // Establecer el orden del filtro
    @Override
    public int getOrder() {
        return -100; // Se ejecuta antes del AuthorizationFilter
    }

    private ServerWebExchange mutateRequest(ServerWebExchange exchange, String jwt) {
        // Extraer el email y roles del token JWT
        String email = jwtUtil.getEmailFromToken(jwt);

        // extraer roles y unirlos en una cadena separada por comas
        String authorities = jwtUtil.getAuthoritiesFromToken(jwt).stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Long userId = jwtUtil.getUserIdFromToken(jwt);

        // Agregar los encabezados personalizados a la solicitud
        return exchange.mutate()
                .request(builder -> {
                    builder.header("X-Auth-Email", email)
                            .header("X-Auth-Roles", authorities);

                        // Solo agregar el header si el ID no es null
                        if (userId != null) {
                            builder.header("X-Auth-User-Id", userId.toString());
                        }
                        }).build();
    }

    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        // Construir ErrorDto JSON usando el status y el mensaje de la excepción
        ErrorDto dto = new ErrorDto(httpStatus.value(), err);
        // Escapar comillas en el mensaje para no romper el JSON
        String safeMessage = dto.getError() == null ? "" : dto.getError().replace("\"", "\\\"");
        String json = String.format("{\"status\":%d,\"error\":\"%s\"}", dto.getStatus(), safeMessage);
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                .bufferFactory().wrap(json.getBytes(StandardCharsets.UTF_8))));
    }
}
    /*
1. Usuario envía request:
POST /gateway/api/v1/productos/crear
Authorization: Bearer eyJhbGc...

        2. AuthenticationFilter se ejecuta:
        ✅ No es ruta pública → Validar token
   ✅ Header presente y con formato "Bearer "
        ✅ Token válido
   ✅ Extrae: email="usuario@ejemplo.com", roles="productos:crear,productos:visualizar"
        ✅ Añade headers: X-Auth-Email, X-Auth-Roles

3. AuthorizationFilter se ejecuta:
        ✅ Lee X-Auth-Roles
   ✅ Verifica si contiene "productos:crear"
        ✅ Permite el acceso

4. Request llega al microservicio con headers:
X-Auth-Email: usuario@ejemplo.com
X-Auth-Roles: productos:crear,productos:visualizar
    */