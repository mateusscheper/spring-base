package scheper.mateus.api.repository;

import org.springframework.stereotype.Repository;

@Repository
@SuppressWarnings("unchecked")
public class ExtendedRepository extends BaseRepository {

    public String healthCheck() {
        return "OK"; // Do your SQL stuff here
    }
}
