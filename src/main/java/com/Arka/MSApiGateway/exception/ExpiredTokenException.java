package com.Arka.MSApiGateway.exception;

/**
 * Excepción lanzada cuando el token JWT ha expirado.
 */
public class ExpiredTokenException extends JwtException {
    public ExpiredTokenException(String message) {
        super(message);
    }

    public ExpiredTokenException(String message, Throwable cause) {
        super(message, cause);
    }
}
