package infragest.infra_auth_service.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO para la respuesta de autenticación.
 * Contiene la información del usuario autenticado y el token JWT generado.
 *
 * @author bunnystring
 * @since 2025-10-28
 * @version 1.0
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuthResponse {

    /**
     * Información segura del usuario autenticado.
     */
    private UserSafeDto user;

    /**
     * Token JWT generado para el usuario autenticado.
     */
    private String token;

}
