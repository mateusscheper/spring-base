package scheper.mateus.api.repository;

import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;

public class BaseRepository {

    @PersistenceContext
    protected EntityManager entityManager;

    protected String sanitizeSortOrder(String sortOrder) {
        if (sortOrder.isBlank()
                || (!sortOrder.equalsIgnoreCase("ASC")
                && !sortOrder.equalsIgnoreCase("DESC"))) {
            return "DESC";
        }
        return sortOrder;
    }

    protected int sanitizeSortBy(int sortBy) {
        return Math.max(sortBy, 1);
    }

    protected int sanitizeSize(int size) {
        if (size < 1) {
            return 10;
        }
        return size;
    }

    protected int sanitizePage(int page) {
        return Math.max(page, 1);
    }

    public <T> T find(Class<T> clazz, Object id) {
        if (id == null) {
            return null;
        }

        return entityManager.find(clazz, id);
    }

    public <T> void persist(T entity) {
        entityManager.persist(entity);
    }

    public <T> T merge(T entity) {
        return entityManager.merge(entity);
    }
}
