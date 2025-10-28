package infragest.infra_auth_service.exception;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.LocalDateTime;
import java.util.Map;

/**
 * Manejador global de excepciones para la aplicación.
 * Intercepta y gestiona las excepciones de tipo {@link UserException}, devolviendo una respuesta HTTP adecuada.
 *
 * @author bunnystring
 * @since 2025-10-28
 * @version 1.0
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    /**
     * Maneja las excepciones de tipo {@link UserException} y construye una respuesta HTTP con detalles del error.
     *
     * @param ex la excepción {@link UserException} lanzada durante la ejecución.
     * @return una instancia de {@link ResponseEntity} con información detallada del error, incluyendo timestamp, código de estado, tipo de error y mensaje.
     */
    @ExceptionHandler(UserException.class)
    public ResponseEntity<?> handleUserException(UserException ex) {
        HttpStatus status = HttpStatus.BAD_REQUEST;
        switch (ex.getType()){
            case NOT_FOUND:
                status = HttpStatus.NOT_FOUND;
                break;
            case EMAIL_IN_USE:
                status = HttpStatus.CONFLICT;
                break;
            case INVALID_PASSWORD:
                status = HttpStatus.BAD_REQUEST;
                break;
            case INVALID_CREDENTIALS:
                status = HttpStatus.BAD_REQUEST;
                break;
            default:
                status = HttpStatus.BAD_REQUEST;
        }
        return ResponseEntity.status(status)
                .body(Map.of(
                        "timestamp", LocalDateTime.now(),
                        "status", status.value(),
                        "error", "User Error",
                        "message", ex.getMessage()
                ));
    }
}
