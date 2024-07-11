package scheper.mateus.api.service;

import io.micrometer.common.util.StringUtils;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import scheper.mateus.api.entity.User;
import scheper.mateus.api.entity.UserInformation;
import scheper.mateus.api.enums.ProviderEnum;
import scheper.mateus.api.exception.BusinessException;
import scheper.mateus.api.repository.AuthRepository;

import static scheper.mateus.api.constant.Messages.EMAIL_ALREADY_REGISTERED;

@Service
public class UserService {

    private final AuthRepository authRepository;

    public UserService(AuthRepository authRepository) {
        this.authRepository = authRepository;
    }

    @Transactional
    public void registerUser(String name, String email, String password, ProviderEnum providerEnum, String idExternal) {
        User user = authRepository.findByEmail(email);
        if (user != null) {
            if (user.hasLocalInformation()) {
                throw new BusinessException(EMAIL_ALREADY_REGISTERED);
            }
        } else {
            user = new User();
            user.setName(name);
            authRepository.persist(user);
        }

        UserInformation userInformation = new UserInformation();
        userInformation.setUser(user);
        userInformation.setEmail(email);
        userInformation.setProvider(providerEnum);

        if (!StringUtils.isBlank(idExternal)) {
            userInformation.setIdExternal(idExternal);
        }

        if (!StringUtils.isBlank(password)) {
            userInformation.setPassword(password);
        }

        authRepository.persist(userInformation);
    }
}
