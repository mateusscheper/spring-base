package scheper.mateus.api.service;

import org.apache.commons.lang3.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.core.env.Environment;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.util.Assert;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;
import scheper.mateus.api.entity.Role;
import scheper.mateus.api.entity.User;
import scheper.mateus.api.enums.SocialProviderEnum;
import scheper.mateus.api.exception.BusinessException;
import scheper.mateus.api.exception.OAuth2AuthenticationProcessingException;
import scheper.mateus.api.repository.UserRepository;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static scheper.mateus.api.constant.Messages.USER_NOT_FOUND;

@Service
public class CustomOAuth2UserService extends DefaultOAuth2UserService implements UserDetailsService {

    private final UserService userService;

    private final UserRepository userRepository;

    private final Environment env;

    protected final Log logger = LogFactory.getLog(this.getClass());

    public CustomOAuth2UserService(UserService userService, Environment env, UserRepository userRepository) {
        this.userService = userService;
        this.env = env;
        this.userRepository = userRepository;
    }

    @Override
    public OAuth2User loadUser(OAuth2UserRequest oAuth2UserRequest) throws OAuth2AuthenticationException {
        OAuth2User oAuth2User = super.loadUser(oAuth2UserRequest);
        try {
            Map<String, Object> attributes = new HashMap<>(oAuth2User.getAttributes());
            String provider = oAuth2UserRequest.getClientRegistration().getRegistrationId();
            if (provider.equals(SocialProviderEnum.LINKEDIN.getProviderType())) {
                populateEmailAddressFromLinkedIn(oAuth2UserRequest, attributes);
            } else if (provider.equals(SocialProviderEnum.INSTAGRAM.getProviderType())) {
                popularNomeEEmailInstagram(oAuth2UserRequest, attributes);
            }
            return userService.processUserRegistration(provider, attributes, null, null);
        } catch (AuthenticationException ex) {
            throw ex;
        } catch (Exception e) {
            e.printStackTrace();
            throw new OAuth2AuthenticationProcessingException(e.getMessage());
        }
    }

    @SuppressWarnings({"rawtypes", "unchecked"})
    public void populateEmailAddressFromLinkedIn(OAuth2UserRequest oAuth2UserRequest, Map<String, Object> attributes) throws OAuth2AuthenticationException {
        String emailEndpointUri = env.getProperty("linkedin.email-address-uri");
        Assert.notNull(emailEndpointUri, "LinkedIn email address end point required");
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + oAuth2UserRequest.getAccessToken().getTokenValue());
        HttpEntity<?> entity = new HttpEntity<>("", headers);
        ResponseEntity<Map> response = restTemplate.exchange(emailEndpointUri, HttpMethod.GET, entity, Map.class);

        if (response.getBody() != null) {
            List<?> list = (List<?>) response.getBody().get("elements");
            Map map = (Map<?, ?>) ((Map<?, ?>) list.get(0)).get("handle~");
            attributes.putAll(map);
        }
    }

    private void popularNomeEEmailInstagram(OAuth2UserRequest oAuth2UserRequest, Map<String, Object> attributes) {
        String endpointConsultaNome = obterUrlConsultaNome(attributes);
        ResponseEntity<Map> response = getRequest(endpointConsultaNome, oAuth2UserRequest.getAccessToken().getTokenValue());
        String username = obterUsername(attributes, response);

        if (!StringUtils.isBlank(username)) {
            attributes.putIfAbsent("email", username);
            popularNomeCompleto(attributes, username);
        }
    }

    private String obterUrlConsultaNome(Map<String, Object> attributes) {
        String endpointConsultaNome = env.getProperty("facebook.username-uri");
        Assert.notNull(endpointConsultaNome, "Endpoint de consulta de username do Instagram requerido.");

        endpointConsultaNome = endpointConsultaNome.replace("{userId}", (String) attributes.get("id"));
        return endpointConsultaNome;
    }

    private ResponseEntity<Map> getRequest(String endpointConsultaNome, String bearerToken) {
        RestTemplate restTemplate = new RestTemplate();

        logger.info("Acessando " + endpointConsultaNome);

        HttpHeaders headers = new HttpHeaders();
        if (!StringUtils.isBlank(bearerToken)) {
            headers.add(HttpHeaders.AUTHORIZATION, "Bearer " + bearerToken);
            logger.info("Token: " + bearerToken);
        }

        HttpEntity<?> entity = new HttpEntity<>("", headers);
        return restTemplate.exchange(endpointConsultaNome, HttpMethod.GET, entity, Map.class);
    }

    private String obterUsername(Map<String, Object> attributes, ResponseEntity<Map> response) {
        String username = null;
        Map responseBody = response.getBody();
        if (responseBody != null) {
            logger.info("ResponseBody: " + responseBody);

            username = (String) responseBody.get("username");
            attributes.put("username", username);
        }
        return username;
    }

    private void popularNomeCompleto(Map<String, Object> attributes, String username) {
        String url = "https://www.instagram.com/" + username + "/channel/?__a=1";

        try {
            ResponseEntity<Map> response = getRequest(url, null);
            Map<String, Object> body = response.getBody();

            if (body != null) {
                Map<String, Map<String, Object>> graphql = (Map<String, Map<String, Object>>) body.get("graphql");
                Map<String, Object> user = graphql.get("user");

                String nomeCompleto = String.valueOf(user.get("full_name"));
                if (!StringUtils.isBlank(nomeCompleto)) {
                    attributes.put("name", nomeCompleto);
                }
            }
        } catch (RestClientException e) {
            attributes.putIfAbsent("name", username);

            logger.error("Ocorreu um erro ao consultar o nome do usuário: \n" +
                    "URL: " + url + "\n " +
                    "Erro: " + e.getMessage());
        }
    }

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String emailAsUsername) throws UsernameNotFoundException {
        User user = userRepository.findByEmail(emailAsUsername);
        String email;
        String password;
        String[] roles;

        if (user == null) {
            user = userRepository.findByEmail(emailAsUsername);
            if (user == null) {
                throw new BusinessException(USER_NOT_FOUND);
            }

        }
        email = user.getEmail();
        password = user.getPassword();
        roles = getRoles(user.getRoles());

        return org.springframework.security.core.userdetails.User
                .builder()
                .username(email)
                .password(password)
                .roles(roles)
                .build();
    }

    private String[] getRoles(List<Role> roles) {
        return roles
                .stream()
                .map(Role::getName)
                .toArray(String[]::new);
    }
}
