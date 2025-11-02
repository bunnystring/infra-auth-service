package infragest.infra_auth_service.service.impl;

import infragest.infra_auth_service.entity.User;
import infragest.infra_auth_service.exception.InvalidJwtAuthenticationException;
import infragest.infra_auth_service.exception.UserException;
import infragest.infra_auth_service.model.AuthResponse;
import infragest.infra_auth_service.model.LoginRequest;
import infragest.infra_auth_service.model.RegisterRequest;
import infragest.infra_auth_service.model.UserSafeDto;
import infragest.infra_auth_service.repository.UserRepository;
import infragest.infra_auth_service.security.JwtUtil;
import infragest.infra_auth_service.service.UserService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

/**
 * Implementación del servicio de usuario.
 * Gestiona el registro y la autenticación de usuarios, así como la generación de tokens JWT.
 *
 * @author bunnystring
 * @since 2025-10-28
 * @version 1.1
 */
@Slf4j
@Service
public class UserServiceImpl implements UserService {

    /**
     * AuthenticationManager: Manejador de autenticaciones de Spring Security.
     */
    private final AuthenticationManager authenticationManager;

    /**
     * UserDetailsService: Servicio para cargar detalles de usuario.
     */
    private final UserDetailsService userDetailsService;

    /**
     * UserRepository: Repositorio de usuarios.
     */
    private final UserRepository userRepository;

    /**
     * PasswordEncoder: Codificador de contraseñas.
     */
    private final PasswordEncoder passwordEncoder;

    /**
     * JwtUtil: Utilidad para generación y validación de JWT.
     */
    private final JwtUtil jwtUtil;

    /**
     * Constructor para la inyección de dependencias.
     * @param authenticationManager
     * @param userDetailsService
     * @param userRepository
     * @param passwordEncoder
     * @param jwtUtil
     */
    public UserServiceImpl(
            AuthenticationManager authenticationManager,
            UserDetailsService userDetailsService,
            UserRepository userRepository,
            PasswordEncoder passwordEncoder,
            JwtUtil jwtUtil)
    {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.jwtUtil = jwtUtil;
    }

    /**
     * Registra un nuevo usuario en el sistema.
     *
     * @param request datos de registro del usuario
     * @return el usuario registrado
     * @throws UserException si el correo ya está registrado
     */
    @Override
    public User registerNewUser(RegisterRequest request) {

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new UserException(
                    request.getEmail() + " is already registered",
                    UserException.Type.EMAIL_IN_USE
            );
        }

        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPassword(passwordEncoder.encode(request.getPassword()));

        return userRepository.save(user);

    }

    /**
     * Auténtica un usuario y genera la respuesta de autenticación con token JWT.
     *
     * @param loginRequest los datos de autenticación del usuario
     * @return la respuesta de autenticación con el usuario seguro y el token generado
     * @throws UserException si las credenciales son inválidas o el usuario no existe
     */
    @Override
    public AuthResponse login(LoginRequest loginRequest) {

        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getEmail(),
                            loginRequest.getPassword()
                    )
            );
        } catch (BadCredentialsException e) {
            throw new UserException("Invalid credentials", UserException.Type.INVALID_CREDENTIALS);
        }

        UserDetails userDetails;
        try {
            userDetails = userDetailsService.loadUserByUsername(loginRequest.getEmail());
        } catch (UsernameNotFoundException e) {
            throw new UserException("User not found", UserException.Type.NOT_FOUND);
        }

        User user = userRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow( () -> new UserException("User not found", UserException.Type.NOT_FOUND));

        String accessToken = jwtUtil.generateToken(userDetails.getUsername());
        String refreshToken = jwtUtil.generateRefreshToken(userDetails.getUsername(),
                7 * 24 * 60 * 60 * 1000L // 7 días en milisegundos
                 );
        UserSafeDto safeUser = new UserSafeDto(user.getName(), user.getEmail());
        return new AuthResponse(safeUser, accessToken, refreshToken);
    }

    /**
     * Renueva el access token y el refresh token usando un refresh token válido.
     *
     * Este método valida el refresh token recibido, verifica su integridad y autenticidad,
     * y si es válido, genera un nuevo access token y un nuevo refresh token para mantener
     * la sesión activa del usuario sin necesidad de re-autenticación.
     *
     * @param refreshToken el refresh token enviado por el cliente
     * @return AuthResponse con el usuario seguro, el nuevo access token y el nuevo refresh token
     * @throws InvalidJwtAuthenticationException si el refresh token es inválido, expirado, mal formado o su firma no es válida
     * @throws UserException si el usuario asociado al token no existe en el sistema
     */
    @Override
    public AuthResponse refreshToken(String refreshToken) {

        if (refreshToken == null || refreshToken.trim().isEmpty()) {
            throw new InvalidJwtAuthenticationException(
                    "Refresh token is missing",
                    InvalidJwtAuthenticationException.Type.AUTHORIZATION_HEADER_MISSING
            );
        }

        String email;

        try {
            email = jwtUtil.extractUsernameFromRefreshToken(refreshToken);
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            throw new InvalidJwtAuthenticationException(
                    "Refresh token expired",
                    InvalidJwtAuthenticationException.Type.UNSUPPORTED_TOKEN
            );
        } catch (io.jsonwebtoken.UnsupportedJwtException e) {
            throw new InvalidJwtAuthenticationException(
                    "Refresh token not supported",
                    InvalidJwtAuthenticationException.Type.UNSUPPORTED_TOKEN
            );
        } catch (io.jsonwebtoken.MalformedJwtException e) {
            throw new InvalidJwtAuthenticationException(
                    "Refresh token malformed",
                    InvalidJwtAuthenticationException.Type.MALFORMED_TOKEN
            );
        } catch (io.jsonwebtoken.SignatureException e) {
            throw new InvalidJwtAuthenticationException(
                    "Refresh token signature error",
                    InvalidJwtAuthenticationException.Type.SIGNATURE_ERROR
            );
        } catch (IllegalArgumentException e) {
            throw new InvalidJwtAuthenticationException(
                    "Refresh token invalid",
                    InvalidJwtAuthenticationException.Type.INVALID_TOKEN
            );
        }

        User user = userRepository.findByEmail(email).orElseThrow(
                () -> new UserException("User not found", UserException.Type.NOT_FOUND));
        UserDetails userDetails = userDetailsService.loadUserByUsername(email);

        String newAccessToken = jwtUtil.generateToken(userDetails.getUsername());
        String newRefreshToken = jwtUtil.generateRefreshToken(userDetails.getUsername(), 7 * 24 * 60 * 60 * 1000L);
        UserSafeDto safeUser = new UserSafeDto(user.getName(), user.getEmail());

        return new AuthResponse(safeUser, newAccessToken, newRefreshToken);
    }
}
