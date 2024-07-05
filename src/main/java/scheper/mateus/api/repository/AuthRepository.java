package scheper.mateus.api.repository;

import io.micrometer.common.util.StringUtils;
import jakarta.persistence.NoResultException;
import org.springframework.stereotype.Repository;
import scheper.mateus.api.entity.User;

import java.util.Optional;

@Repository
public class AuthRepository extends BaseRepository {

    public Optional<User> findByEmail(String email) {
        if (StringUtils.isBlank(email)) {
            return Optional.empty();
        }

        try {
            return Optional.ofNullable(entityManager.createQuery("SELECT u " +
                            "FROM User u " +
                            "WHERE u.email = :email " +
                            "AND u.active", User.class)
                    .setParameter("email", email)
                    .getSingleResult());
        } catch (NoResultException e) {
            return Optional.empty();
        }
    }

    public boolean isEmailAlreadyRegistered(String email) {
        if (!StringUtils.isBlank(email)) {
            return false;
        }

        return (boolean) entityManager.createNativeQuery("SELECT EXISTS(" +
                        "SELECT 1 " +
                        "FROM base.\"user\" " +
                        "WHERE email = :email)")
                .setParameter("email", email)
                .getSingleResult();
    }
}
