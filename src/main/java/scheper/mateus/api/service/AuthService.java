package scheper.mateus.api.service;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import scheper.mateus.api.dto.LoginDTO;
import scheper.mateus.api.entity.Role;
import scheper.mateus.api.entity.User;
import scheper.mateus.api.exception.BusinessException;
import scheper.mateus.api.repository.AuthRepository;

import java.time.Instant;
import java.util.List;

@Service
public class AuthService {

    private final AuthRepository authRepository;

    private final JwtEncoder encoder;

    private final PasswordEncoder passwordEncoder;

    private final JwtDecoder jwtDecoder;

    @Value("${jwt.expiration}")
    private Long expiration;

    public AuthService(AuthRepository authRepository, JwtEncoder encoder, PasswordEncoder passwordEncoder, JwtDecoder jwtDecoder) {
        this.authRepository = authRepository;
        this.encoder = encoder;
        this.passwordEncoder = passwordEncoder;
        this.jwtDecoder = jwtDecoder;
    }

    public String login(LoginDTO loginDTO) {
        String errorMessage = "Invalid e-mail or password.";
        User user = authRepository.findByEmail(loginDTO.getEmail())
                .orElseThrow(() -> new BusinessException(errorMessage));

        if (!passwordMatches(loginDTO.getPassword(), user.getPassword())) {
            throw new BusinessException(errorMessage);
        }

        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .expiresAt(now.plusSeconds(expiration))
                .subject(user.getEmail())
                .claim("name", user.getName())
                .claim("roles", user
                        .getRoles()
                        .stream()
                        .map(Role::getName)
                        .toList())
                .build();

        return encoder.encode(JwtEncoderParameters.from(claims)).getTokenValue();
    }

    private boolean passwordMatches(String sentPassword, String databasePassword) {
        return passwordEncoder.matches(sentPassword, databasePassword);
    }

    public User getUserFromJwt(HttpServletRequest httpRequest) {
        String email = getEmailFromJwt(httpRequest);
        if (StringUtils.isBlank(email)) {
            throw new BusinessException("Invalid user.");
        }

        User user = getUserByEmail(email);
        if (user == null) {
            throw new BusinessException("Invalid user.");
        }

        return user;
    }

    public String getEmailFromJwt(HttpServletRequest httpRequest) {
        Jwt jwt = getJwtFromRequest(httpRequest);
        return jwt.getSubject();
    }

    private Jwt getJwtFromRequest(HttpServletRequest httpRequest) {
        String authorization = httpRequest.getHeader("Authorization");
        if (StringUtils.isBlank(authorization)) {
            throw new BusinessException("Authorization header is missing.");
        }
        String token = authorization.replace("Bearer ", "");
        if (StringUtils.isBlank(token)) {
            throw new BusinessException("Authorization header is missing.");
        }
        Jwt jwt = jwtDecoder.decode(token);
        Instant jwtExpiration = jwt.getExpiresAt();
        if (jwtExpiration == null || jwtExpiration.isBefore(Instant.now())) {
            throw new BusinessException("Token is expired.");
        }
        return jwt;
    }

    public List<String> getRolesFromJwt(HttpServletRequest httpRequest) {
        Jwt jwt = getJwtFromRequest(httpRequest);
        return jwt.getClaimAsStringList("roles");
    }

    public User getUserByEmail(String email) {
        if (StringUtils.isBlank(email)) {
            return null;
        }

        return authRepository.findByEmail(email).orElse(null);
    }

    public void validate(HttpServletRequest httpRequest) {
        getJwtFromRequest(httpRequest);
    }
}
