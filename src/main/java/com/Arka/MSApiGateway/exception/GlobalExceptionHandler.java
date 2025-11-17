package com.Arka.MSApiGateway.exception;

import com.Arka.MSApiGateway.dto.ErrorDto;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ExpiredTokenException.class)
    public ResponseEntity<ErrorDto> handleExpiredToken(ExpiredTokenException ex) {
        ErrorDto body = new ErrorDto(HttpStatus.UNAUTHORIZED.value(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

    @ExceptionHandler(InvalidTokenException.class)
    public ResponseEntity<ErrorDto> handleInvalidToken(InvalidTokenException ex) {
        ErrorDto body = new ErrorDto(HttpStatus.UNAUTHORIZED.value(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

    @ExceptionHandler(JwtException.class)
    public ResponseEntity<ErrorDto> handleJwtGeneral(JwtException ex) {
        ErrorDto body = new ErrorDto(HttpStatus.UNAUTHORIZED.value(), ex.getMessage());
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorDto> handleAny(Exception ex) {
        ErrorDto body = new ErrorDto(HttpStatus.INTERNAL_SERVER_ERROR.value(), "Error interno");
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }
}
