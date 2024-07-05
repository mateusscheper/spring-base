package scheper.mateus.api.constant;

public class Messages {

    private Messages() {
        throw new IllegalStateException("Utility class");
    }

    public static final String AUTHORIZATION_HEADER_IS_MISSING = "Authorization header is missing.";
    public static final String INVALID_E_MAIL_OR_PASSWORD = "Invalid e-mail or password.";
    public static final String EMAIL_ALREADY_REGISTERED = "E-mail already registered.";
    public static final String TOKEN_IS_EXPIRED = "Token is expired.";
    public static final String USER_NOT_FOUND = "User not found.";
}
