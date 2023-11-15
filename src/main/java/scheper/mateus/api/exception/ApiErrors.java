package scheper.mateus.api.exception;

import java.util.Collections;
import java.util.List;
import java.util.Objects;

public class ApiErrors {

    private List<String> errors;

    public ApiErrors() {
    }

    public ApiErrors(List<String> errors) {
        this.errors = errors;
    }

    public ApiErrors(String errorMessage) {
        this.errors = Collections.singletonList(errorMessage);
    }

    public List<String> getErrors() {
        return errors;
    }

    public void setErrors(List<String> errors) {
        this.errors = errors;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        ApiErrors apiErrors = (ApiErrors) o;
        return Objects.equals(errors, apiErrors.errors);
    }

    @Override
    public int hashCode() {
        return Objects.hash(errors);
    }
}
