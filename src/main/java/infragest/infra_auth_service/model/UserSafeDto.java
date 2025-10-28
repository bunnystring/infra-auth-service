package infragest.infra_auth_service.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO seguro para exponer únicamente los datos públicos del usuario,
 * sin incluir ni el id ni el password.
 *
 * @author bunnystring
 * @since 2025-10-28
 * @version 1.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserSafeDto {

    /**
     * Nombre del usuario.
     */
    private String name;

    /**
     * Correo electrónico del usuario.
     */
    private String email;

}
