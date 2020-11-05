package com.tutorial.springsecurity.jwt;

import com.google.common.net.HttpHeaders;
import io.jsonwebtoken.security.Keys;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

// get config values from application.properties
//@ConfigurationProperties(prefix = "application.jwt")
@Configuration
public class JwtConfig {

    String key ="fjeawkfkewjafklawejfklawjfklafaewjhfawekfhwaeufhawiawefhaewflf1223awfefawefeaw";
    String bearer ="Bearer ";
    Integer expirationAfterDays = 14;

    private String secretKey;
    private String tokenPrefix;
    private Integer tokenExpirationAfterDays;

    public JwtConfig() {
        this.secretKey = key;
        this.tokenPrefix = bearer;
        this.tokenExpirationAfterDays = expirationAfterDays;
    }

    public String getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(String secretKey) {
        this.secretKey = secretKey;
    }

    public String getTokenPrefix() {
        return tokenPrefix;
    }

    public void setTokenPrefix(String tokenPrefix) {
        this.tokenPrefix = tokenPrefix;
    }

    public Integer getTokenExpirationAfterDays() {
        return tokenExpirationAfterDays;
    }

    public void setTokenExpirationAfterDays(Integer tokenExpirationAfterDays) {
        this.tokenExpirationAfterDays = tokenExpirationAfterDays;
    }

    public String getAuthorizationHeader() {
        return HttpHeaders.AUTHORIZATION;
    }
}
