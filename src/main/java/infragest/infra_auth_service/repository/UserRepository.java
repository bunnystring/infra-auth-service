package infragest.infra_auth_service.repository;

import infragest.infra_auth_service.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

/**
 * Interface repository para consultas a la entidad User.
 * Proporciona métodos para consultar usuarios por su email y verificar su existencia.
 *
 * @author bunnystring
 * @since 2025-10-27
 * @version 1.0
 */
public interface UserRepository extends JpaRepository<User, UUID> {

    /**
     * Busca un usuario por su dirección de correo electrónico.
     *
     * @param email la dirección de correo electrónico del usuario a buscar.
     * @return un Optional que contiene el usuario si existe, o vacío si no se encuentra.
     */
    Optional<User> findByEmail(String email);

    /**
     * Verifica si existe un usuario con la dirección de correo electrónico especificada.
     *
     * @param email la dirección de correo electrónico a verificar.
     * @return true si existe un usuario con el correo proporcionado, false en caso contrario.
     */
    boolean existsByEmail(String email);
}
