package infragest.infra_auth_service.controller;

import infragest.infra_auth_service.model.AuthResponse;
import infragest.infra_auth_service.model.LoginRequest;
import infragest.infra_auth_service.model.RegisterRequest;
import infragest.infra_auth_service.repository.UserRepository;
import infragest.infra_auth_service.security.JwtUtil;
import infragest.infra_auth_service.service.UserService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.responses.ApiResponses;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

/**
 * Controlador REST para operaciones de autenticación de usuarios.
 * Proporciona endpoints para registro y login con generación de JWT.
 *
 * @author bunnystring
 * @since 2025-10-28
 * @version 1.0
 */
@Tag(name = "Autenticación", description = "Operaciones de registro, login y refresh JWT")
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
    @Operation(
            summary = "Registro de usuario",
            description = "Crea un nuevo usuario y devuelve un token JWT válido al registrar. También realiza login de inmediato."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Usuario registrado exitosamente y logueado",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Datos inválidos"),
            @ApiResponse(responseCode = "409", description = "Correo electrónico ya registrado")
    })
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
    @Operation(
            summary = "Login de usuario",
            description = "Autentica un usuario y devuelve un token JWT (y refresh token si aplica) si las credenciales son válidas."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Login exitoso",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "400", description = "Credenciales inválidas"),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
    })
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody @Valid LoginRequest loginRequest){
        AuthResponse authResponse = userService.login(loginRequest);
        return ResponseEntity.ok(authResponse);
    }

    /**
     * Renueva el access token usando un refresh token válido.
     *
     * @param body El refresh token enviado por el cliente.
     * @return Un ResponseEntity con un nuevo access token (y opcionalmente un nuevo refresh token) o un error.
     */
    @Operation(
            summary = "Refresh Token",
            description = "Renueva el access token usando el refresh token enviado por el cliente (clave 'refreshToken' en el body JSON)."
    )
    @ApiResponses(value = {
            @ApiResponse(responseCode = "200", description = "Token renovado correctamente",
                    content = @Content(schema = @Schema(implementation = AuthResponse.class))),
            @ApiResponse(responseCode = "401", description = "Refresh token inválido o expirado"),
            @ApiResponse(responseCode = "404", description = "Usuario no encontrado")
    })
    @PostMapping("/refresh")
    public ResponseEntity<?> refresh(@RequestBody Map<String, String> body) {
        String refreshToken = body.get("refreshToken");
        AuthResponse authResponse = userService.refreshToken(refreshToken);
        return ResponseEntity.ok(authResponse);
    }
}
