package scheper.mateus.api.service;

import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import scheper.mateus.api.enums.ProviderEnum;
import scheper.mateus.api.repository.AuthRepository;

import static scheper.mateus.api.utils.ConvertUtils.asString;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService {

    private final AuthRepository authRepository;

    private final UserService userService;

    public CustomOAuth2UserService(AuthRepository authRepository, UserService userService) {
        this.authRepository = authRepository;
        this.userService = userService;
    }

    @Transactional
    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(userRequest);

        String email = oAuth2User.getAttribute("email");
        if (email == null) {
            throw new OAuth2AuthenticationException("Email not found from OAuth2 provider");
        }

        ProviderEnum providerEnum = ProviderEnum.fromRegistrationId(userRequest.getClientRegistration().getRegistrationId());
        if (authRepository.isEmailExistsByProvider(email, providerEnum)) {
            return oAuth2User;
        }

        userService.registerUser(oAuth2User.getAttribute("name"), email, null, providerEnum, asString(oAuth2User.getAttribute("id")));

        return oAuth2User;
    }
}
