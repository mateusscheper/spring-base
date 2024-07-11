package scheper.mateus.api.service;

import io.micrometer.common.util.StringUtils;
import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;
import scheper.mateus.api.dto.LoginDTO;
import scheper.mateus.api.dto.RegisterDTO;
import scheper.mateus.api.entity.User;
import scheper.mateus.api.enums.SocialProviderEnum;
import scheper.mateus.api.exception.BusinessException;
import scheper.mateus.api.repository.AuthRepository;

import static scheper.mateus.api.constant.Messages.AUTHORIZATION_HEADER_IS_MISSING;
import static scheper.mateus.api.constant.Messages.EMAIL_ALREADY_REGISTERED;
import static scheper.mateus.api.constant.Messages.TOKEN_IS_EXPIRED;

@Service
public class AuthService {

    private final AuthRepository authRepository;

    private final JwtDecoder jwtDecoder;

    private final PasswordEncoder passwordEncoder;

    private final RedisService redisService;

    private final JwtService jwtService;

    public AuthService(AuthRepository authRepository, JwtDecoder jwtDecoder, PasswordEncoder passwordEncoder, RedisService redisService, JwtService jwtService) {
        this.authRepository = authRepository;
        this.jwtDecoder = jwtDecoder;
        this.passwordEncoder = passwordEncoder;
        this.redisService = redisService;
        this.jwtService = jwtService;
    }

    public String login(LoginDTO loginDTO) {
        String errorMessage = "Invalid e-mail or password.";
        User user = authRepository.findByEmail(loginDTO.getEmail())
                .orElseThrow(() -> new BusinessException(errorMessage));

        if (!passwordMatches(loginDTO.getPassword(), user.getPassword())) {
            throw new BusinessException(errorMessage);
        }

        return jwtService.generateJwt(user, SocialProviderEnum.LOCAL.getProviderType());
    }

    public void logout() {
        Jwt jwt = getJwtFromRequest(getHttpServletRequest());
        redisService.blackListJwt(jwt.getTokenValue());
    }

    private boolean passwordMatches(String sentPassword, String databasePassword) {
        return passwordEncoder.matches(sentPassword, databasePassword);
    }

    public String encodePassword(String password) {
        return passwordEncoder.encode(password);
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
        user.setPassword(encodePassword(registerDTO.getPassword()));

        authRepository.persist(user);
    }
}
