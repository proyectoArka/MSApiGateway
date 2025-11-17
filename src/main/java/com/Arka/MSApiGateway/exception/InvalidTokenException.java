package com.Arka.MSApiGateway.exception;

/**
 * Excepción lanzada cuando el token JWT es inválido por firma, formato u otros errores.
 */
public class InvalidTokenException extends JwtException {
    public InvalidTokenException(String message) {
        super(message);
    }

    public InvalidTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
