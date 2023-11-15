package scheper.mateus.api.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;

import java.io.Serial;
import java.io.Serializable;

import static scheper.mateus.api.utils.ConvertUtils.asLong;
import static scheper.mateus.api.utils.ConvertUtils.asString;

@Builder
@Getter
@Setter
@EqualsAndHashCode
@AllArgsConstructor
public class BaseDTO implements Serializable {

    @Serial
    private static final long serialVersionUID = 1L;

    private Long id;

    private String name;

    public BaseDTO(Object[] data) {
        int i = 0;
        this.id = asLong(data[i++]);
        this.name = asString(data[i]);
    }
}
