package scheper.mateus.api.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Getter
@Setter
@Table(schema = User.BASE_SCHEMA, name = "role")
public class Role {

    @Id
    @GeneratedValue(generator = "role_id_seq", strategy = GenerationType.SEQUENCE)
    @SequenceGenerator(schema = User.BASE_SCHEMA, name = "role_id_seq", sequenceName = User.BASE_SCHEMA + ".role_id_seq", allocationSize = 1)
    private Long idrole;

    @Column(nullable = false, unique = true)
    private String name;

    private String description;
}