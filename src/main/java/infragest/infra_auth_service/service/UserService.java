package infragest.infra_auth_service.service;

import infragest.infra_auth_service.entity.User;
import infragest.infra_auth_service.model.AuthResponse;
import infragest.infra_auth_service.model.LoginRequest;
import infragest.infra_auth_service.model.RegisterRequest;

/**
 * Servicio para operaciones relacionadas con usuarios.
 * Define el contrato para el registro de nuevos usuarios y la autenticación.
 *
 * @author bunnystring
 * @since 2025-10-28
 * @version 1.0
 */
public interface UserService {

    /**
     * Registra un nuevo usuario en el sistema.
     *
     * @param request los datos de registro del usuario
     * @return el usuario registrado
     */
    User registerNewUser(RegisterRequest request);


    /**
     * Autentica un usuario en el sistema
     *
     * @param loginRequest los datos de autenticación del usuario
     * @return AuthResponse
     */
    AuthResponse login(LoginRequest loginRequest);
}
