package infragest.infra_auth_service.model;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO para la solicitud de inicio de sesión.
 * Contiene los campos requeridos para autenticar un usuario.
 *
 * @author bunnystring
 * @since 2025-10-28
 * @version 1.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class LoginRequest {

    /**
     * Correo electrónico del usuario.
     * No puede estar vacío.
     */
    @NotBlank(message = "Email is required")
    private String email;

    /**
     * Contraseña del usuario.
     * No puede estar vacía.
     */
    @NotBlank(message = "Password is required")
    private String password;
}
