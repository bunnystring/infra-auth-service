package infragest.infra_auth_service.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO para la solicitud de registro de usuario.
 * Contiene los campos necesarios para el registro.
 *
 * @author bunnystring
 * @since 2025-10-28
 * @version 1.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    /**
     * Nombre del usuario.
     * No debe estar vacío y tiene un máximo de 50 caracteres.
     */
    @NotBlank(message = "Name is required")
    @Size(max = 50)
    private String name;

    /**
     * Correo electrónico del usuario.
     * Debe estar en formato válido y no puede estar vacío.
     */
    @NotBlank(message = "Email is required")
    @Email(message = "Email format is invalid")
    private String email;

    /**
     * Contraseña del usuario.
     * Debe tener al menos 6 caracteres y no puede estar vacía.
     */
    @NotBlank(message = "Password is required")
    @Size(min = 6, message = "The password must be at least 6 characters long")
    private String password;

}
