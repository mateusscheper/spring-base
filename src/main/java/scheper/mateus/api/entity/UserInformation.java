package scheper.mateus.api.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import scheper.mateus.api.enums.ProviderEnum;

import static scheper.mateus.api.entity.User.BASE_SCHEMA;

@Entity
@Getter
@Setter
@Table(schema = BASE_SCHEMA, name = "user_information")
public class UserInformation {

    @Id
    @GeneratedValue(generator = "user_information_id_seq", strategy = GenerationType.SEQUENCE)
    @SequenceGenerator(schema = BASE_SCHEMA, name = "user_information_id_seq", sequenceName = BASE_SCHEMA + ".user_information_id_seq", allocationSize = 1)
    private Long idUserInformation;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "id_user")
    private User user;

    @Column
    private String idExternal;

    @Column(nullable = false)
    private String email;

    @Column(length = 100)
    private String password;

    @Enumerated(EnumType.STRING)
    private ProviderEnum provider;
}
