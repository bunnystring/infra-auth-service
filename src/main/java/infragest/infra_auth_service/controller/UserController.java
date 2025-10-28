package infragest.infra_auth_service.controller;

import infragest.infra_auth_service.model.AuthResponse;
import infragest.infra_auth_service.model.LoginRequest;
import infragest.infra_auth_service.model.RegisterRequest;
import infragest.infra_auth_service.repository.UserRepository;
import infragest.infra_auth_service.security.JwtUtil;
import infragest.infra_auth_service.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

/**
 * Controlador REST para operaciones de autenticación de usuarios.
 * Proporciona endpoints para registro y login con generación de JWT.
 *
 * @author bunnystring
 * @since 2025-10-28
 * @version 1.0
 */
@CrossOrigin("*")
@RestController
@RequestMapping("/auth")
public class UserController {

    /**
     * UserService: Servicio de operaciones de usuario.
     */
    private final UserService userService;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param userService servicio de usuario
     */
    public UserController(
            UserService userService )
    {
        this.userService = userService;
    }

    /**
     * Registra un nuevo usuario en el sistema.
     *
     * @param request El objeto con los datos necesarios para el registro.
     * @return Un ResponseEntity con la respuesta de autenticación o error.
     */
    @PostMapping("/register")
    public ResponseEntity<?> register(@RequestBody @Valid RegisterRequest request) {

        // Registrar usuario
        userService.registerNewUser(request);

        // hacer Login
        LoginRequest loginRequest = new LoginRequest(request.getEmail(), request.getPassword());
        AuthResponse authResponse = userService.login(loginRequest);

        return ResponseEntity.ok(authResponse);
    }

    /**
     * Auténtica a un usuario y genera un token JWT si las credenciales son válidas.
     *
     * @param loginRequest El objeto con el email y password del usuario.
     * @return Un ResponseEntity con el token JWT o un mensaje de error.
     */
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid LoginRequest loginRequest){
        AuthResponse authResponse = userService.login(loginRequest);
        return ResponseEntity.ok(authResponse);
    }
}
