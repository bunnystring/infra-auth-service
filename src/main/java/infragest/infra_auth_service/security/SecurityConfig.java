package infragest.infra_auth_service.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Configuración principal de seguridad para la aplicación.
 * Define el filtro JWT, las reglas de autorización y el manejo de sesiones.
 *
 * @author bunnystring
 */
@Configuration
public class SecurityConfig {

    /**
     * JwtAuthFilter: filtro de autenticación jwt.
     */
    private final JwtAuthFilter jwtAuthFilter;

    /**
     * UserDetailServiceImpl: servicio user detail.
     */
    private final UserDetailServiceImpl userDetailService;

    public SecurityConfig(
            JwtAuthFilter jwtAuthFilter,
            UserDetailServiceImpl userDetailService)
    {
        this.jwtAuthFilter = jwtAuthFilter;
        this.userDetailService = userDetailService;
    }

    /**
     * Configura la cadena de filtros de seguridad y las reglas de autorización HTTP.
     *
     * @param httpSecurity objeto de configuración de seguridad HTTP
     * @return instancia de SecurityFilterChain
     * @throws Exception en caso de error de configuración
     */
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/auth/**").permitAll()
                        .anyRequest().authenticated()
                )
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .userDetailsService(userDetailService)
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return httpSecurity.build();
    }

    /**
     * Expone el AuthenticationManager como bean para la autenticación.
     *
     * @param configuration configuración de autenticación
     * @return bean de AuthenticationManager
     * @throws Exception en caso de error de configuración
     */
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }
}
