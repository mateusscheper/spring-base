package scheper.mateus.api.service;

import org.springframework.cache.annotation.CachePut;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.stereotype.Service;

import static scheper.mateus.api.configuration.RedisCacheConfig.BLACKLIST_CACHE_NAME;

@Service
public class RedisService {

    @CachePut(BLACKLIST_CACHE_NAME)
    public String blackListJwt(String jwt) {
        return jwt;
    }

    @Cacheable(value = BLACKLIST_CACHE_NAME, unless = "#result == null")
    public String getJwtBlackList(String jwt) {
        return null;
    }
}
