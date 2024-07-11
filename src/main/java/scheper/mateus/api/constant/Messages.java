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
    public static final String PASSWORD_MUST_BE_AT_LEAST_6_CHARACTERS = "Password must be at least 6 characters.";
    public static final String REDIRECT_URL_NOT_ALLOWED = "Redirect URL not allowed.";
}
