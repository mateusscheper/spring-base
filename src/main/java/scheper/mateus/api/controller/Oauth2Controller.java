package scheper.mateus.api.controller;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

@RestController
@RequestMapping("/")
public class Oauth2Controller {

    @GetMapping
    public Map<String, Object> user(@AuthenticationPrincipal OAuth2User oauth2User) {
        return oauth2User.getAttributes();
    }
}
