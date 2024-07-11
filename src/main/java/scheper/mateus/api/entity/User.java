package scheper.mateus.api.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.JoinTable;
import jakarta.persistence.ManyToMany;
import jakarta.persistence.OneToMany;
import jakarta.persistence.SequenceGenerator;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import scheper.mateus.api.enums.ProviderEnum;

import java.util.ArrayList;
import java.util.List;

@Entity
@Getter
@Setter
@Table(schema = User.BASE_SCHEMA, name = "user")
public class User {

    public static final String BASE_SCHEMA = "base";

    @Id
    @GeneratedValue(generator = "user_id_seq", strategy = GenerationType.SEQUENCE)
    @SequenceGenerator(schema = BASE_SCHEMA, name = "user_id_seq", sequenceName = BASE_SCHEMA + ".user_id_seq", allocationSize = 1)
    private Long idUser;

    @Column(nullable = false, length = 120)
    private String name;

    private boolean active = true;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(schema = BASE_SCHEMA, name = "user_role",
            joinColumns = @JoinColumn(name = "id_user"),
            inverseJoinColumns = @JoinColumn(name = "id_role"))
    private List<Role> roles = new ArrayList<>();

    @OneToMany(mappedBy = "user", fetch = FetchType.LAZY)
    private List<UserInformation> userInformations = new ArrayList<>();

    public String getLocalEmail() {
        return userInformations
                .stream()
                .filter(provider -> provider.getProvider().equals(ProviderEnum.LOCAL))
                .findFirst()
                .map(UserInformation::getEmail)
                .orElse(null);
    }

    public String getPassword() {
        return userInformations
                .stream()
                .filter(provider -> provider.getProvider().equals(ProviderEnum.LOCAL))
                .findFirst()
                .map(UserInformation::getPassword)
                .orElse(null);
    }

    public boolean hasLocalInformation() {
        return userInformations
                .stream()
                .anyMatch(provider -> provider.getProvider().equals(ProviderEnum.LOCAL));
    }
}
