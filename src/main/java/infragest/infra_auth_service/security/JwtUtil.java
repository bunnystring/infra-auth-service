package infragest.infra_auth_service.security;

import infragest.infra_auth_service.exception.InvalidJwtAuthenticationException;
import io.jsonwebtoken.*;
import jakarta.annotation.PostConstruct;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

/**
 * Utilidad para la generación y validación de JWTs.
 * Proporciona métodos para crear tokens, extraer información del token y validar su integridad.
 *
 * @author bunnystring
 */
@Component
public class JwtUtil {

    @Value("${spring.security.oauth2.resourceserver.jwt.secret}")
    private String jwtSecretBase64;

    @Value("${spring.security.oauth2.resourceserver.jwt.expiration}")
    private long jwtExpirationMs;

    private Key secretKey;

    @PostConstruct
    public void init() {
        byte[] keyBytes = Base64.getDecoder().decode(jwtSecretBase64);
        this.secretKey = new SecretKeySpec(keyBytes, "HmacSHA256");
    }

    /**
     * Genera un token JWT usando el nombre de usuario dado.
     *
     * @param username El nombre de usuario (suele ser el email)
     * @return Token JWT generado
     */
    public String generateToken(String username) {
        return Jwts.builder()
                .setSubject(username)
                .claim("type", "access")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + jwtExpirationMs))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Genera un refresh token JWT usando el nombre de usuario dado.
     * El token tendrá el claim "type" = "refresh" para distinguirlo de un access token.
     * La expiración del refresh token generalmente es mayor que la del access token.
     *
     * @param username El nombre de usuario (suele ser el email)
     * @param refreshExpirationMs Tiempo de expiración en milisegundos para el refresh token
     * @return Refresh token JWT generado
     */
    public String generateRefreshToken(String username, long refreshExpirationMs) {
        return Jwts.builder()
                .setSubject(username)
                .claim("type", "refresh")
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + refreshExpirationMs))
                .signWith(secretKey, SignatureAlgorithm.HS256)
                .compact();
    }

    /**
     * Extrae el email (subject) de un token JWT.
     *
     * @param token El token JWT
     * @return El email extraído del token
     */
    public String getEmailFromToken(String token){
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    /**
     * Válida la integridad y validez de un token JWT.
     *
     * @param token El token JWT
     * @return true si es válido, false en caso contrario
     */
    public boolean validateToken(String token){
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
            return true;
        } catch (JwtException | IllegalArgumentException e){
            return false;
        }
    }

    /**
     * Extrae el email (subject) de un refresh token JWT.
     * Válida el token y lanza las excepciones específicas de JWT si no es válido.
     *
     * @param refreshToken El refresh token JWT
     * @return El email extraído del refresh token
     * @throws ExpiredJwtException si el token está expirado
     * @throws UnsupportedJwtException si el token no es soportado
     * @throws MalformedJwtException si el token está mal formado
     * @throws SignatureException si la firma es inválida
     * @throws IllegalArgumentException si el token es nulo o vacío
     */
    public String extractUsernameFromRefreshToken(String refreshToken) {

        Claims claims = Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(refreshToken)
                .getBody();

        // Verifica que sea realmente un refresh token
        if (!"refresh".equals(claims.get("type"))) {
            throw new InvalidJwtAuthenticationException(
                    "Invalid token type for refresh",
                    InvalidJwtAuthenticationException.Type.INVALID_TOKEN
            );
        }
        return claims.getSubject();
    }
}
