package scheper.mateus.api.enums;

public enum ProviderEnum {

    LOCAL,
    GOOGLE,
    FACEBOOK,
    GITHUB,
    LINKEDIN;

    public static ProviderEnum fromRegistrationId(String registrationId) {
        for (ProviderEnum providerEnum : values()) {
            if (providerEnum.name().equalsIgnoreCase(registrationId)) {
                return providerEnum;
            }
        }
        return null;
    }
}
