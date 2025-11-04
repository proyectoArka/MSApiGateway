package com.Arka.MSApiGateway.config.filter;

import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.List;

@Component
public class AuthorizationFilter extends AbstractGatewayFilterFactory<AuthorizationFilter.Config> {

    public AuthorizationFilter() {
        // Se requiere para que Spring sepa cómo inicializar el filtro
        super(Config.class);
    }

    // Clase de configuración que recibe el permiso requerido del YML
    public static class Config {
        private String requiredAuthority;

        public String getRequiredAuthority() { return requiredAuthority; }
        public void setRequiredAuthority(String requiredAuthority) { this.requiredAuthority = requiredAuthority; }
    }

    // Necesario para leer el parámetro 'requiredAuthority' del application.yml
    @Override
    public List<String> shortcutFieldOrder() {
        return Arrays.asList("requiredAuthority");
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {

            // 1. Obtener los roles del usuario de la cabecera (inyectados por AuthenticationFilter)
            String userRolesHeader = exchange.getRequest().getHeaders().getFirst("X-Auth-Roles");
            String requiredPermission = config.getRequiredAuthority();

            // 2. Verificar la existencia y el permiso
            if (userRolesHeader == null || !hasRequiredAuthority(userRolesHeader, requiredPermission)) {
                // Si falta la cabecera (error de flujo) o no tiene el permiso, denegar
                return this.onError(exchange, "Acceso Denegado. Permiso requerido: " + requiredPermission, HttpStatus.FORBIDDEN); // 403 Forbidden
            }

            // 3. Si tiene el permiso, pasar al microservicio de destino
            return chain.filter(exchange);
        };
    }

    // Lógica para verificar si el string de roles del usuario contiene la autoridad requerida
    private boolean hasRequiredAuthority(String userRolesHeader, String requiredAuthority) {
        // userRolesHeader: string separado por comas (ej: "productos:crear,usuarios:crear_admin")
        return Arrays.stream(userRolesHeader.split(","))
                .anyMatch(role -> role.trim().equals(requiredAuthority.trim()));
    }

    // Manejo de errores reactivo para el Gateway (403 Forbidden)
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        exchange.getResponse().setStatusCode(httpStatus);
        exchange.getResponse().getHeaders().add("Content-Type", "application/json");
        return exchange.getResponse().writeWith(Mono.just(exchange.getResponse()
                .bufferFactory().wrap(
                        ("{\"error\":\"" + err + "\"}").getBytes(StandardCharsets.UTF_8)
                )));
    }
}

/*
*
* 1. Usuario envía request:
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
   *
   * */

/*
* 1. Request:
   DELETE /gateway/api/v1/productos/eliminar/123
   Authorization: Bearer eyJhbGc...

2. AuthenticationFilter:
   ✅ Valida JWT
   ✅ Extrae permisos: "productos:crear,productos:visualizar"
   ✅ Añade header: X-Auth-Roles: productos:crear,productos:visualizar

3. AuthorizationFilter:
   ✅ Lee X-Auth-Roles
   ✅ Convierte a lista: ["productos:crear", "productos:visualizar"]
   ✅ Permiso requerido: "productos:eliminar"
   ❌ ¿Lo tiene? → NO
   ❌ Deniega el acceso

4. Response:
   HTTP 403 Forbidden
   {
     "error": "Acceso denegado: se requiere el permiso productos:eliminar"
   }
   * */
