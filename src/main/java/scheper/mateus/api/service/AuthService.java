package scheper.mateus.api.service;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import scheper.mateus.api.dto.LoginDTO;
import scheper.mateus.api.dto.RegisterDTO;
import scheper.mateus.api.entity.Role;
import scheper.mateus.api.entity.User;
import scheper.mateus.api.exception.BusinessException;
import scheper.mateus.api.repository.AuthRepository;

import java.time.Instant;

import static scheper.mateus.api.constant.Messages.AUTHORIZATION_HEADER_IS_MISSING;
import static scheper.mateus.api.constant.Messages.EMAIL_ALREADY_REGISTERED;
import static scheper.mateus.api.constant.Messages.TOKEN_IS_EXPIRED;

@Service
public class AuthService {

    private final AuthRepository authRepository;

    private final JwtEncoder encoder;

    private final PasswordEncoder passwordEncoder;

    private final JwtDecoder jwtDecoder;

    private final RedisService redisService;

    @Value("${jwt.expiration}")
    private Long expiration;

    public AuthService(AuthRepository authRepository, JwtEncoder encoder, PasswordEncoder passwordEncoder, JwtDecoder jwtDecoder, RedisService redisService) {
        this.authRepository = authRepository;
        this.encoder = encoder;
        this.passwordEncoder = passwordEncoder;
        this.jwtDecoder = jwtDecoder;
        this.redisService = redisService;
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

    public void logout() {
        Jwt jwt = getJwtFromRequest(getHttpServletRequest());
        redisService.blackListJwt(jwt.getTokenValue());
    }

    private boolean passwordMatches(String sentPassword, String databasePassword) {
        return passwordEncoder.matches(sentPassword, databasePassword);
    }

    private HttpServletRequest getHttpServletRequest() {
        RequestAttributes requestAttributes = RequestContextHolder.getRequestAttributes();
        if (!(requestAttributes instanceof ServletRequestAttributes)) {
            return null;
        }
        return ((ServletRequestAttributes) requestAttributes).getRequest();
    }

    private Jwt getJwtFromRequest(HttpServletRequest httpRequest) {
        String token = extractJwtToken(httpRequest);
        if (StringUtils.isBlank(token)) {
            throw new AccessDeniedException(AUTHORIZATION_HEADER_IS_MISSING);
        }

        Jwt jwt = jwtDecoder.decode(token);
        String jwtBlackList = redisService.getJwtBlackList(jwt.getTokenValue());
        if (jwtBlackList != null) {
            throw new AccessDeniedException(TOKEN_IS_EXPIRED);
        }

        return jwt;
    }

    private String extractJwtToken(HttpServletRequest httpRequest) {
        String authorization = httpRequest.getHeader("Authorization");
        if (StringUtils.isBlank(authorization)) {
            throw new AccessDeniedException(AUTHORIZATION_HEADER_IS_MISSING);
        }

        return authorization.replace("Bearer ", "");
    }

    @Transactional
    public void register(RegisterDTO registerDTO) {
        String email = registerDTO.getEmail().trim();
        if (authRepository.findByEmail(email).isPresent()) {
            throw new BusinessException(EMAIL_ALREADY_REGISTERED);
        }

        User user = new User();
        user.setEmail(email);
        user.setName(registerDTO.getName().trim());
        user.setPassword(passwordEncoder.encode(registerDTO.getPassword()));

        authRepository.persist(user);
    }
}
