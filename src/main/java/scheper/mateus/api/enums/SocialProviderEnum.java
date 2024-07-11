package scheper.mateus.api.enums;

import lombok.Getter;

@Getter
public enum SocialProviderEnum {

    FACEBOOK("facebook", "Facebook"),
    INSTAGRAM("instagram", "Instagram"),
    TWITTER("twitter", "Twitter"),
    LINKEDIN("linkedin", "LinkedIn"),
    GOOGLE("google", "Google"),
    GITHUB("github", "GitHub"),
    LOCAL("local", "MTS");

    private final String providerType;

    private final String name;

    SocialProviderEnum(final String providerType, final String name) {
        this.providerType = providerType;
        this.name = name;
    }

    public static SocialProviderEnum parseType(String providerType) {
        for (SocialProviderEnum socialProviderEnum : values()) {
            if (socialProviderEnum.getProviderType().equalsIgnoreCase(providerType)) {
                return socialProviderEnum;
            }
        }
        return null;
    }

}
