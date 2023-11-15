package scheper.mateus.api.service;

import org.springframework.stereotype.Service;
import scheper.mateus.api.repository.ExtendedRepository;

@Service
public class BaseService {

    private final ExtendedRepository extendedRepository;

    public BaseService(ExtendedRepository extendedRepository) {
        this.extendedRepository = extendedRepository;
    }

    public String healthCheck() {
        return extendedRepository.healthCheck();
    }
}
