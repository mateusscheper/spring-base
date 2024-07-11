package scheper.mateus.api.repository;

import jakarta.persistence.NoResultException;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Repository;
import scheper.mateus.api.entity.User;

@Repository
public class UserRepository extends BaseRepository {

    public User findByEmail(String email) {
        if (StringUtils.isBlank(email)) {
            return null;
        }

        try {
            return entityManager.createQuery("SELECT u FROM User u WHERE u.email = :email", User.class)
                    .setParameter("email", email)
                    .getSingleResult();
        } catch (NoResultException e) {
            return null;
        }
    }

    public boolean existsById(int idUser) {
        return (boolean) entityManager.createNativeQuery("SELECT EXISTS(SELECT 1 FROM base.\"user\" WHERE id_user = :idUser)")
                .setParameter("idUser", idUser)
                .getSingleResult();
    }

    public boolean existsByEmail(String email) {
        return (boolean) entityManager.createNativeQuery("SELECT EXISTS(SELECT 1 FROM base.\"user\" WHERE email = :email)")
                .setParameter("email", email)
                .getSingleResult();
    }
}
