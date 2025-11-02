package infragest.infra_auth_service.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO para la respuesta de autenticación.
 * Contiene la información del usuario autenticado, el access token y el refresh del token generado.
 *
 * @author bunnystring
 * @since 2025-10-28
 * @version 1.1
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
     * Access token JWT generado para el usuario autenticado.
     */
    private String accessToken;

    /**
     * Refresh token JWT generado para el usuario autenticado.
     */
    private String refreshToken;
}
