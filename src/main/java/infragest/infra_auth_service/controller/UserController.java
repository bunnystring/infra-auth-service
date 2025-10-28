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
     * AuthenticationManager: Manejador de autenticación de Spring Security.
     */
    private final AuthenticationManager authenticationManager;

    /**
     * JwtUtil: Utilidad para la generación y validación de JWT.
     */
    private final JwtUtil jwtUtil;

    /**
     * UserDetailsService: Servicio para cargar detalles de usuario.
     */
    private final UserDetailsService userDetailsService;

    /**
     * UserService: Servicio de operaciones de usuario.
     */
    private final UserService userService;

    /**
     * UserRepository: Repositorio de usuarios.
     */
    private final UserRepository userRepository;

    /**
     * Constructor para la inyección de dependencias.
     *
     * @param authenticationManager manejador de autenticación
     * @param jwtUtil utilidad para manejo de JWT
     * @param userDetailsService servicio para obtener detalles de usuario
     * @param userService servicio de usuario
     * @param userRepository repositorio de usuarios
     */
    public UserController(
            AuthenticationManager authenticationManager,
            JwtUtil jwtUtil,
            UserDetailsService userDetailsService,
            UserService userService,
            UserRepository userRepository)
    {
        this.authenticationManager = authenticationManager;
        this.jwtUtil = jwtUtil;
        this.userDetailsService = userDetailsService;
        this.userService = userService;
        this.userRepository = userRepository;
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
