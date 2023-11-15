package scheper.mateus.api.exception;

import com.fasterxml.jackson.databind.exc.InvalidDefinitionException;
import org.springframework.context.support.DefaultMessageSourceResolvable;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.validation.BindException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.util.List;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

@RestControllerAdvice
public class ApplicationControllerAdvice {

    @ExceptionHandler(BusinessException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiErrors handleException(BusinessException e) {
        e.printStackTrace();

        String message = e.getMessage();

        if (message.startsWith("{") && message.endsWith("}")) {
            String messageNoBraces = message.replace("{", "").replace("}", "");
            try {
                message = ResourceBundle.getBundle("messages").getString(messageNoBraces);
            } catch (MissingResourceException ignored) {
                // ignored
            }
        }

        return new ApiErrors(message);
    }

    @ExceptionHandler(BindException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiErrors handleException(BindException e) {
        e.printStackTrace();

        return new ApiErrors(e.getAllErrors()
                .stream()
                .map(DefaultMessageSourceResolvable::getDefaultMessage)
                .toList());
    }

    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    @ResponseStatus(HttpStatus.METHOD_NOT_ALLOWED)
    public ApiErrors handleException(HttpRequestMethodNotSupportedException e) {
        e.printStackTrace();

        return new ApiErrors(String.format("Method %s not allowed.", e.getMethod()));
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiErrors handleException(MethodArgumentNotValidException e) {
        e.printStackTrace();

        List<String> errosEmString = e.getAllErrors()
                .stream()
                .map(DefaultMessageSourceResolvable::getDefaultMessage)
                .toList();
        return new ApiErrors(errosEmString);
    }

    @ExceptionHandler({
            HttpMessageNotReadableException.class,
            InvalidDefinitionException.class
    })
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public ApiErrors handleException(Exception e) {
        e.printStackTrace();

        return new ApiErrors("Invalid data.");
    }

    @ExceptionHandler(RuntimeException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public ApiErrors handleException(RuntimeException e) {
        e.printStackTrace();

        return new ApiErrors("An internal server error has ocurred.");
    }
}
