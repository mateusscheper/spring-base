package scheper.mateus.api.dto;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;


@Getter
@Setter
public class RegisterDTO implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    @NotBlank(message = "Invalid name.")
    private String name;

    @NotBlank(message = "Invalid e-mail.")
    private String email;

    @NotBlank(message = "Invalid password.")
    private String password;
}
