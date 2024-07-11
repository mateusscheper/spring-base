package scheper.mateus.api.service;

import jakarta.transaction.Transactional;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.stereotype.Service;
import scheper.mateus.api.dto.LocalUser;
import scheper.mateus.api.dto.OAuth2UserInfo;
import scheper.mateus.api.dto.OAuth2UserInfoFactory;
import scheper.mateus.api.dto.SignUpRequest;
import scheper.mateus.api.entity.User;
import scheper.mateus.api.enums.SocialProviderEnum;
import scheper.mateus.api.exception.BusinessException;
import scheper.mateus.api.exception.OAuth2AuthenticationProcessingException;
import scheper.mateus.api.repository.UserRepository;

import java.util.Map;

@Service
public class UserService {

    private final UserRepository userRepository;

    private final AuthService authService;

    public UserService(UserRepository userRepository, AuthService authService) {
        this.userRepository = userRepository;
        this.authService = authService;
    }

    @Transactional
    public LocalUser processUserRegistration(String registrationId, Map<String, Object> attributes, OidcIdToken idToken, OidcUserInfo userInfo) {
        OAuth2UserInfo oAuth2UserInfo = OAuth2UserInfoFactory.getOAuth2UserInfo(registrationId, attributes);

        if (StringUtils.isEmpty(oAuth2UserInfo.getName())) {
            throw new OAuth2AuthenticationProcessingException("Nome não encontrado. Certifique-se de que o e-mail esteja configurado como público e refaça o procedimento.");
        } else if (StringUtils.isEmpty(oAuth2UserInfo.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("E-mail não encontrado. Certifique-se de que o e-mail esteja configurado como público e refaça o procedimento.");
        }

        SignUpRequest userDetails = toUserRegistrationObject(registrationId, oAuth2UserInfo);
        User user = userRepository.findByEmail(oAuth2UserInfo.getEmail());
        if (user != null) {
            SocialProviderEnum provider = user.getProvider();

            if (!provider.getProviderType().equals(registrationId) && !provider.equals(SocialProviderEnum.LOCAL)) {
                throw new OAuth2AuthenticationProcessingException("Email already registered with " + provider.getName() + ". Please, login using your " + provider.getName() + " account.");
            }

            user = updateExistingUser(user, oAuth2UserInfo);
        } else {
            user = registerNewUser(userDetails);
        }

        return LocalUser.create(user, attributes, idToken, userInfo);
    }

    private User updateExistingUser(User user, OAuth2UserInfo oAuth2UserInfo) {
        user.setName(oAuth2UserInfo.getName());
        return userRepository.merge(user);
    }

    @Transactional
    public User registerNewUser(final SignUpRequest signUpRequest) throws BusinessException {
        if (signUpRequest.getUserID() != null && userRepository.existsById(signUpRequest.getUserID().intValue())) {
            throw new OAuth2AuthenticationProcessingException("Usuário com ID " + signUpRequest.getUserID() + " já existe.");
        } else if (userRepository.existsByEmail(signUpRequest.getEmail())) {
            throw new OAuth2AuthenticationProcessingException("Usuário com e-mail " + signUpRequest.getEmail() + " já existe.");
        }

        User user = buildUser(signUpRequest);
        userRepository.persist(user);
        return user;
    }

    private User buildUser(SignUpRequest formDTO) {
        User user = new User();
        user.setName(formDTO.getDisplayName());
        user.setEmail(formDTO.getEmail());
        user.setPassword(authService.encodePassword(formDTO.getPassword()));

        user.setProvider(formDTO.getSocialProvider());
        user.setExternalId(formDTO.getProviderUserId());

        return user;
    }

    private SignUpRequest toUserRegistrationObject(String registrationId, OAuth2UserInfo oAuth2UserInfo) {
        return SignUpRequest
                .getBuilder()
                .addProviderUserID(oAuth2UserInfo.getId())
                .addDisplayName(oAuth2UserInfo.getName())
                .addEmail(oAuth2UserInfo.getEmail())
                .addSocialProvider(toSocialProvider(registrationId))
                .addPassword("vlZqbdXd16chMFSN6kWkvlZqbdXd16chMFSN6kWkvlZqbdXd16chMFSN6kWk") // TODO
                .build();
    }

    private SocialProviderEnum toSocialProvider(String providerId) {
        for (SocialProviderEnum SocialProviderEnum : SocialProviderEnum.values()) {
            if (SocialProviderEnum.getProviderType().equals(providerId)) {
                return SocialProviderEnum;
            }
        }
        return SocialProviderEnum.LOCAL;
    }
}
