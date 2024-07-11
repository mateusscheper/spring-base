package scheper.mateus.api.repository;

import io.micrometer.common.util.StringUtils;
import jakarta.persistence.NoResultException;
import org.springframework.stereotype.Repository;
import scheper.mateus.api.entity.User;
import scheper.mateus.api.enums.ProviderEnum;

import java.util.Optional;

import static scheper.mateus.api.constant.Queries.EMAIL;

@Repository
public class AuthRepository extends BaseRepository {

    public User findByEmail(String email) {
        if (StringUtils.isBlank(email)) {
            return null;
        }

        try {
            return entityManager.createQuery("SELECT u " +
                            "FROM User u " +
                            "JOIN FETCH u.userInformations ui " +
                            "WHERE ui.email = :email " +
                            "AND u.active", User.class)
                    .setParameter(EMAIL, email)
                    .getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }

    public Optional<User> findByEmailAndProvider(String email, ProviderEnum providerEnum) {
        if (StringUtils.isBlank(email)) {
            return Optional.empty();
        }

        try {
            return Optional.ofNullable(entityManager.createQuery("SELECT u " +
                            "FROM User u " +
                            "JOIN FETCH u.userInformations ui " +
                            "WHERE ui.email = :email " +
                            "AND ui.provider = :provider " +
                            "AND u.active", User.class)
                    .setParameter(EMAIL, email)
                    .setParameter("provider", providerEnum)
                    .getSingleResult());
        } catch (NoResultException e) {
            return Optional.empty();
        }
    }

    public boolean isEmailExistsByProvider(String email, ProviderEnum providerEnum) {
        if (StringUtils.isBlank(email)) {
            return false;
        }

        return (boolean) entityManager.createNativeQuery("SELECT EXISTS(" +
                        "SELECT 1 " +
                        "FROM base.user_information " +
                        "WHERE email = :email " +
                        "AND provider = :provider)")
                .setParameter(EMAIL, email)
                .setParameter("provider", providerEnum.name())
                .getSingleResult();
    }
}
