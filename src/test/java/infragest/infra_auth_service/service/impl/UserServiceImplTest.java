package infragest.infra_auth_service.service.impl;

import infragest.infra_auth_service.entity.User;
import infragest.infra_auth_service.exception.UserException;
import infragest.infra_auth_service.model.AuthResponse;
import infragest.infra_auth_service.model.LoginRequest;
import infragest.infra_auth_service.model.RegisterRequest;
import infragest.infra_auth_service.repository.UserRepository;
import infragest.infra_auth_service.security.JwtUtil;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.*;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

/**
 * Pruebas unitarias para la clase {@link UserServiceImpl}.
 *
 * Se valida el correcto funcionamiento de los métodos principales como el registro de usuarios,
 * autenticación y manejo de credenciales inválidas, usando mocks de las dependencias.
 *
 * @author bunnystring
 * @since 2025-11-03
 */
public class UserServiceImplTest {

    @Mock AuthenticationManager authenticationManager;
    @Mock UserDetailsService userDetailsService;
    @Mock UserRepository userRepository;
    @Mock PasswordEncoder passwordEncoder;
    @Mock JwtUtil jwtUtil;

    @InjectMocks UserServiceImpl userService;

    /**
     * Inicializa los mocks antes de cada prueba.
     */
    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    /**
     * Verifica que el registro de un nuevo usuario exitoso retorna el usuario persisitido.
     */
    @Test
    void registerNewUser_success_createsUser() {
        RegisterRequest request = new RegisterRequest("Camilo", "camilo@test.com", "secret");
        when(userRepository.existsByEmail("camilo@test.com")).thenReturn(false);
        when(passwordEncoder.encode("secret")).thenReturn("hashed_secret");
        User savedUser = new User();
        savedUser.setName("Camilo");
        savedUser.setEmail("camilo@test.com");
        savedUser.setPassword("hashed_secret");
        when(userRepository.save(any(User.class))).thenReturn(savedUser);
        User user = userService.registerNewUser(request);

        assertEquals("Camilo", user.getName());
        assertEquals("camilo@test.com", user.getEmail());
        assertEquals("hashed_secret", user.getPassword());
        verify(userRepository).save(any(User.class));
    }

    /**
     * Verifica que se lanza una excepción {@link UserException} cuando el email ya está registrado.
     */
    @Test
    void registerNewUser_existingEmail_throwsUserException() {
        RegisterRequest request = new RegisterRequest("Jane", "jane@test.com", "pass");
        when(userRepository.existsByEmail("jane@test.com")).thenReturn(true);

        UserException ex = assertThrows(UserException.class, () -> userService.registerNewUser(request));

        assertEquals(UserException.Type.EMAIL_IN_USE, ex.getType());
        assertTrue(ex.getMessage().contains("already registered"));
    }

    /**
     * Prueba el login exitoso, esperando una respuesta con tokens y usuario seguro.
     */
    @Test
    void login_success_returnsAuthResponse() {
        LoginRequest loginRequest = new LoginRequest("test@test.com", "pass");
        User user = new User();
        user.setName("Test");
        user.setEmail("test@test.com");

        UserDetails userDetails = mock(UserDetails.class);
        when(userDetails.getUsername()).thenReturn("test@test.com");

        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(mock(Authentication.class));
        when(userDetailsService.loadUserByUsername("test@test.com")).thenReturn(userDetails);
        when(userRepository.findByEmail("test@test.com")).thenReturn(Optional.of(user));
        when(jwtUtil.generateToken("test@test.com")).thenReturn("accessToken");
        when(jwtUtil.generateRefreshToken(eq("test@test.com"), anyLong())).thenReturn("refreshToken");

        AuthResponse resp = userService.login(loginRequest);

        assertNotNull(resp);
        assertEquals("accessToken", resp.getAccessToken());
        assertEquals("refreshToken", resp.getRefreshToken());
        assertEquals("Test", resp.getUser().getName());
    }

    /**
     * Verifica que un login con credenciales inválidas lanza {@link UserException}.
     */
    @Test
    void login_invalidCredentials_throwsUserException() {
        LoginRequest loginRequest = new LoginRequest("test@test.com", "badpass");
        doThrow(new BadCredentialsException("Invalid")).when(authenticationManager)
                .authenticate(any(UsernamePasswordAuthenticationToken.class));

        UserException ex = assertThrows(UserException.class, () -> userService.login(loginRequest));
        assertEquals(UserException.Type.INVALID_CREDENTIALS, ex.getType());
    }

    /**
     * Verifica que si el usuario no existe al intentar login, se lanza {@link UserException}.
     */
    @Test
    void login_userNotFound_throwsUserException() {
        LoginRequest loginRequest = new LoginRequest("noexist@test.com", "pwd");

        // Simula autenticación correcta, pero usuario no existe ni en UserDetails ni en repo
        when(authenticationManager.authenticate(any(UsernamePasswordAuthenticationToken.class)))
                .thenReturn(mock(Authentication.class));
        when(userDetailsService.loadUserByUsername("noexist@test.com"))
                .thenThrow(new UsernameNotFoundException("Not found"));

        // El repo puede devolver Optional.empty() también, pero con UserDetails lanzando, es suficiente
        UserException ex = assertThrows(UserException.class, () -> userService.login(loginRequest));
        assertEquals(UserException.Type.NOT_FOUND, ex.getType());
    }

    /**
     * Prueba que refreshToken retorna un AuthResponse válido si el token es correcto y el usuario existe.
     */
    @Test
    void refreshToken_success_returnsAuthResponse() {
        String refreshToken = "refresh_token_mock";
        String email = "user@test.com";
        User user = new User();
        user.setName("Test User");
        user.setEmail(email);

        // Mock uso correcto de JWT y repo
        when(jwtUtil.extractUsernameFromRefreshToken(refreshToken)).thenReturn(email);
        when(userRepository.findByEmail(email)).thenReturn(Optional.of(user));

        // Mock UserDetails (debe retornar el mismo email en getUsername)
        UserDetails userDetails = mock(UserDetails.class);
        when(userDetailsService.loadUserByUsername(email)).thenReturn(userDetails);
        when(userDetails.getUsername()).thenReturn(email);

        when(jwtUtil.generateToken(email)).thenReturn("newAccessToken");
        when(jwtUtil.generateRefreshToken(eq(email), anyLong())).thenReturn("newRefreshToken");

        AuthResponse response = userService.refreshToken(refreshToken);

        assertNotNull(response);
        assertEquals("Test User", response.getUser().getName());
        assertEquals("newAccessToken", response.getAccessToken());
        assertEquals("newRefreshToken", response.getRefreshToken());
    }

    /**
     * Prueba que si el refresh token es nulo o vacío se lanza InvalidJwtAuthenticationException.
     */
    @Test
    void refreshToken_nullOrEmpty_throwsInvalidJwtAuthenticationException() {
        assertThrows(
                infragest.infra_auth_service.exception.InvalidJwtAuthenticationException.class,
                () -> userService.refreshToken(null)
        );
        assertThrows(
                infragest.infra_auth_service.exception.InvalidJwtAuthenticationException.class,
                () -> userService.refreshToken(" ")
        );
    }

    /**
     * Prueba que si el usuario no existe para el email extraído del refresh token se lanza UserException.
     */
    @Test
    void refreshToken_userNotFound_throwsUserException() {
        String refreshToken = "jwtvalid";
        String email = "missing@user.com";

        when(jwtUtil.extractUsernameFromRefreshToken(refreshToken)).thenReturn(email);
        when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

        assertThrows(
                UserException.class,
                () -> userService.refreshToken(refreshToken)
        );
    }

    /**
     * Prueba que si jwtUtil lanza excepción al extraer el username, se propaga un InvalidJwtAuthenticationException.
     */
    @Test
    void refreshToken_invalidToken_throwsInvalidJwtAuthenticationException() {
        String refreshToken = "badtoken";
        when(jwtUtil.extractUsernameFromRefreshToken(refreshToken))
                .thenThrow(new infragest.infra_auth_service.exception.InvalidJwtAuthenticationException("Invalid", null));

        assertThrows(
                infragest.infra_auth_service.exception.InvalidJwtAuthenticationException.class,
                () -> userService.refreshToken(refreshToken)
        );
    }
}
