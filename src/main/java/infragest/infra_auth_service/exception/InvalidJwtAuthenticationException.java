package infragest.infra_auth_service.exception;

/**
 * Excepción personalizada para errores relacionados con la autenticación JWT.
 * Proporciona diferentes tipos de error a través del enum Type.
 *
 * @author bunnystring
 * @since 2025-11-02
 * @version 1.0
 */
public class InvalidJwtAuthenticationException extends RuntimeException {

    /**
     * Enum que representa los diferentes tipos de errores de autenticación JWT.
     */
    public enum Type {
        INVALID_TOKEN,             // El token JWT es inválido
        EXPIRED_TOKEN,             // El token JWT ha expirado
        UNSUPPORTED_TOKEN,         // El token JWT no es soportado
        MALFORMED_TOKEN,           // El token JWT está mal formado
        SIGNATURE_ERROR,           // La firma del token JWT es incorrecta
        AUTHORIZATION_HEADER_MISSING // Falta el header de autorización o es incorrecto
    }

    private final Type type;

    /**
     * Crea una nueva InvalidJwtAuthenticationException con el mensaje y tipo especificados.
     *
     * @param message el mensaje descriptivo de la excepción.
     * @param type el tipo de error de autenticación JWT asociado a la excepción.
     */
    public InvalidJwtAuthenticationException(String message, Type type) {
        super(message);
        this.type = type;
    }

    /**
     * Obtiene el tipo de error de autenticación JWT asociado a la excepción.
     *
     * @return el tipo de error {@link Type}.
     */
    public Type getType() {
        return type;
    }
}