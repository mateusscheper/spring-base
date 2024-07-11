package scheper.mateus.api.dto;


import scheper.mateus.api.configuration.oauth2.FacebookOAuth2UserInfo;
import scheper.mateus.api.configuration.oauth2.GithubOAuth2UserInfo;
import scheper.mateus.api.configuration.oauth2.GoogleOAuth2UserInfo;
import scheper.mateus.api.configuration.oauth2.InstagramOAuth2UserInfo;
import scheper.mateus.api.configuration.oauth2.LinkedinOAuth2UserInfo;
import scheper.mateus.api.enums.SocialProviderEnum;
import scheper.mateus.api.exception.BusinessException;

import java.util.Map;

public class OAuth2UserInfoFactory {

    private OAuth2UserInfoFactory() {
        throw new UnsupportedOperationException();
    }

    public static OAuth2UserInfo getOAuth2UserInfo(String registrationId, Map<String, Object> attributes) {
        if (registrationId.equalsIgnoreCase(SocialProviderEnum.GOOGLE.getProviderType())) {
            return new GoogleOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(SocialProviderEnum.FACEBOOK.getProviderType())) {
            return new FacebookOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(SocialProviderEnum.INSTAGRAM.getProviderType())) {
            return new InstagramOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(SocialProviderEnum.GITHUB.getProviderType())) {
            return new GithubOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(SocialProviderEnum.LINKEDIN.getProviderType())) {
            return new LinkedinOAuth2UserInfo(attributes);
        } else if (registrationId.equalsIgnoreCase(SocialProviderEnum.TWITTER.getProviderType())) {
            return new GithubOAuth2UserInfo(attributes);
        } else {
            throw new BusinessException("Login with " + registrationId + " is not supported yet.");
        }
    }
}
