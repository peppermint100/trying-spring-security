package com.tutorial.springsecurity.jwt;

import com.google.common.base.Strings;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.crypto.SecretKey;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public class JwtTokenVerifier extends OncePerRequestFilter {
    private final JwtConfig jwtConfig;
    private final SecretKey secretKey;

    public JwtTokenVerifier(JwtConfig jwtConfig, SecretKey secretKey) {
        this.jwtConfig = jwtConfig;
        this.secretKey = secretKey;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {


        //get token from header
        String authorizationHeader = request.getHeader(jwtConfig.getAuthorizationHeader());

        // if token is invalid
        if(Strings.isNullOrEmpty(authorizationHeader) || !authorizationHeader.startsWith("Bearer ")){
            // inherit filter chain from post filter
            filterChain.doFilter(request, response);
            return;
        }

        String token = authorizationHeader.replace(jwtConfig.getTokenPrefix(), "");

        try{
           Jws<Claims> claimsJws = Jwts
                   .parserBuilder()
                   .setSigningKey(secretKey)
                   .build().parseClaimsJws(token);

            Claims body = claimsJws.getBody();

            String username = body.getSubject();
            // get claims named "authorities" from token
            List<Map<String, String>> authorities = (List<Map<String, String>>) body.get("authorities");

            Set<SimpleGrantedAuthority> simpleGrantedAuthoritySet =
                    authorities
                    .stream()
                    .map(a -> new SimpleGrantedAuthority(a.get("authority")))
                    .collect(Collectors.toSet());

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    simpleGrantedAuthoritySet
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
        } catch (JwtException e){
            throw new IllegalStateException(String.format("Token %s cannot be trusted", token));
        }

        // send prev and current request, response to next filter(which can be the endpoint)
        filterChain.doFilter(request, response);
    }
}
