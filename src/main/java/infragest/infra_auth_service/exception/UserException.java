package infragest.infra_auth_service.exception;

/**
 * Excepción personalizada para errores relacionados con la entidad User.
 * Proporciona diferentes tipos de error a través del enum Type.
 *
 * @author bunnystring
 * @since 2025-10-28
 * @version 1.0
 */
public class UserException extends RuntimeException{

    /**
     * Enum que representa los diferentes tipos de errores de usuario.
     */
    public enum Type {
        NOT_FOUND,            // Usuario no encontrado
        EMAIL_IN_USE,         // El correo electrónico ya está en uso
        INVALID_PASSWORD,     // La contraseña proporcionada es inválida
        INVALID_CREDENTIALS,  // Las credenciales proporcionadas son inválidas
    }

    private final Type type;

    /**
     * Crea una nueva UserException con el mensaje y tipo especificados.
     *
     * @param message el mensaje descriptivo de la excepción.
     * @param type el tipo de error de usuario asociado a la excepción.
     */
    public UserException(String message, Type type) {
        super(message);
        this.type = type;
    }

    /**
     * Obtiene el tipo de error de usuario asociado a la excepción.
     *
     * @return el tipo de error {@link Type}.
     */
    public Type getType() {
        return type;
    }
}
