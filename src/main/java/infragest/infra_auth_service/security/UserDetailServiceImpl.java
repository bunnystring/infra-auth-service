package infragest.infra_auth_service.security;


import infragest.infra_auth_service.entity.User;
import infragest.infra_auth_service.repository.UserRepository;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Collections;

/**
 * Implementación de {@link UserDetailsService} para la autenticación de usuarios.
 * Carga los detalles del usuario desde el repositorio utilizando el email como identificador.
 *
 * @author bunnystring
 * @since 2025-10-28
 * @version 1.0
 */
@Service
public class UserDetailServiceImpl implements UserDetailsService {

    /**
     * UserRepository: repositorio de usuarios para el acceso a datos de la entidad User.
     */
    private final UserRepository userRepository;

    /**
     * Constructor con los parametros de la clase.
     * @param userRepository
     */
    public UserDetailServiceImpl(
            UserRepository userRepository)
    {
        this.userRepository = userRepository;
    }

    /**
     * Carga los detalles de un usuario a partir de su dirección de correo electrónico.
     *
     * @param email la dirección de correo electrónico del usuario.
     * @return los detalles del usuario como una instancia de {@link UserDetails}.
     * @throws UsernameNotFoundException si no se encuentra un usuario con el email proporcionado.
     */
    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(email)
                .orElseThrow( () -> new UsernameNotFoundException("Usuario no encontrado con email: " + email));
        return new org.springframework.security.core.userdetails.User(
                user.getEmail(),
                user.getPassword(),
                Collections.singleton(new SimpleGrantedAuthority("ADMIN"))
        );
    }
}
