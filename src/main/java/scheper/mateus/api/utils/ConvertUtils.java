package scheper.mateus.api.utils;

import io.micrometer.common.util.StringUtils;

public class ConvertUtils {

    private ConvertUtils() {
        throw new IllegalStateException("Utility class");
    }

    public static Long parseLong(String value) {
        if (StringUtils.isBlank(value)) {
            return null;
        }

        try {
            return Long.parseLong(value);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public static Short parseShort(String value) {
        if (StringUtils.isBlank(value)) {
            return null;
        }

        try {
            return Short.parseShort(value);
        } catch (NumberFormatException e) {
            return null;
        }
    }

    public static Long asLong(Object obj) {
        if (obj == null) {
            return null;
        }

        try {
            return ((Number) obj).longValue();
        } catch (Exception e) {
            return null;
        }
    }

    public static Integer asInteger(Object obj) {
        if (obj == null) {
            return null;
        }

        try {
            return ((Number) obj).intValue();
        } catch (Exception e) {
            return null;
        }
    }

    public static Short asShort(Object obj) {
        if (obj == null) {
            return null;
        }

        try {
            return ((Number) obj).shortValue();
        } catch (Exception e) {
            return null;
        }
    }

    public static String asString(Object obj) {
        if (obj == null) {
            return null;
        }

        try {
            return ((String) obj);
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean asBoolean(Object obj) {
        if (obj == null) {
            return false;
        }

        try {
            return ((boolean) obj);
        } catch (Exception e) {
            return false;
        }
    }
}
