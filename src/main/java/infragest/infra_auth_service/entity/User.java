package infragest.infra_auth_service.entity;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;

/**
 * Entidad que representa a un usuario del sistema.
 * Hereda campos de auditoría ({@Code id}, {@code createdAt}, {@code lastModified}) y control de concurrencia optimista ({@code version})
 * desde {@link BaseEntity}.
 * @author bunnystring
 * @since 2025-10-27
 * @version 1.0
 */
@Getter
@Setter
@NoArgsConstructor
@Entity
@Table(name = "users")
public class User extends BaseEntity{

    /**
     * Nombre del usuario.
     */
    @NotBlank(message = "El nombre es obligatorio")
    @Size(max = 50)
    private String name;

    /**
     * Correo electronico del usuario
     * Debe ser unico y valido
     */
    @NotBlank(message = "El email es obligatorio")
    @Email(message = "El email debe ser válido")
    @Column(unique = true)
    private String email;

    /**
     * Contraseña del usuario.
     * Debe tener al menos 6 caracteres.
     */
    @NotBlank(message = "La contraseña es obligatoria")
    @Size(min = 6, message = "La contraseña debe tener al menos 6 caracteres")
    private String password;

    /**
     *Indica si el correo electroníco del usuario ha sido verificado.
     */
    @Column(name = "email_verified")
    private boolean emailVerified = false;

}
