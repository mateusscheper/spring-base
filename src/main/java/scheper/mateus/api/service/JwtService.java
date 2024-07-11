package scheper.mateus.api.service;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimsSet;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtEncoderParameters;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import scheper.mateus.api.dto.LocalUser;
import scheper.mateus.api.entity.Role;
import scheper.mateus.api.entity.User;
import scheper.mateus.api.enums.SocialProviderEnum;
import scheper.mateus.api.repository.UserRepository;

import java.time.Instant;

@Service
public class JwtService {

    private final UserRepository userRepository;

    private final JwtEncoder encoder;

    private final RedisService redisService;

    private final JwtDecoder jwtDecoder;

    @Value("${jwt.expiration}")
    private Long expiration;

    public JwtService(UserRepository userRepository, JwtEncoder encoder, RedisService redisService, @Qualifier("jwtDecoder") JwtDecoder jwtDecoder) {
        this.userRepository = userRepository;
        this.encoder = encoder;
        this.redisService = redisService;
        this.jwtDecoder = jwtDecoder;
    }

    @Transactional
    public String generateJwtTokenLoginOauth2(Authentication authentication) {
        LocalUser userPrincipal = (LocalUser) authentication.getPrincipal();
        String email = userPrincipal.getUser().getEmail();
        User user = userRepository.findByEmail(email);
        return generateJwt(user, SocialProviderEnum.GITHUB.getProviderType());
    }

    public String generateJwt(User user, String provider) {
        Instant now = Instant.now();

        JwtClaimsSet claims = JwtClaimsSet.builder()
                .issuer("self")
                .issuedAt(now)
                .issuer(provider)
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

    public boolean isTokenValid(String token) {
        try {
            Jwt jwt = jwtDecoder.decode(token);
            String jwtBlackList = redisService.getJwtBlackList(jwt.getTokenValue());
            return jwtBlackList == null;
        } catch (Exception e) {
            return false;
        }
    }

    public String getEmailFromJwt(String token) {
        Jwt jwt = jwtDecoder.decode(token);
        return jwt.getSubject();
    }
}
