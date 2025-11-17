package com.Arka.MSApiGateway.exception;

/**
 * Excepción base para errores relacionados con JWT.
 */
public class JwtException extends RuntimeException {
    public JwtException(String message) {
        super(message);
    }

    public JwtException(String message, Throwable cause) {
        super(message, cause);
    }
}

