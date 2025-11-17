package com.Arka.MSApiGateway.exception;

/**
 * Excepción lanzada cuando falta el header Authorization o tiene formato incorrecto.
 * El mensaje por defecto se guarda en la propia excepción (no en la lógica del filtro).
 */
public class MissingJwtException extends JwtException {
    public MissingJwtException() {
        super("JWT no presente o formato incorrecto");
    }

    public MissingJwtException(Throwable cause) {
        super("JWT no presente o formato incorrecto", cause);
    }
}

