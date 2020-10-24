package com.tutorial.springsecurity.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@Configuration
@EnableWebSecurity
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private final PasswordEncoder passwordEncoder;

    public ApplicationSecurityConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("api/**").hasRole(ApplicationUserRole.STUDENT.name())
                .antMatchers(HttpMethod.DELETE, "/management/api/**").hasAnyAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.POST, "/management/api/**").hasAnyAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.PUT, "/management/api/**").hasAnyAuthority(ApplicationUserPermission.COURSE_WRITE.getPermission())
                .antMatchers(HttpMethod.GET,"/management/api/**").hasAnyRole(ApplicationUserRole.ADMIN.name(), ApplicationUserRole.ADMINTRAINEE.name())
                .anyRequest()
                .authenticated()
                .and()
                .httpBasic();
    }

    @Override
    @Bean
    protected UserDetailsService userDetailsService() {
       UserDetails pepperUser = User.builder()
                .username("pepper")
                .password(passwordEncoder.encode("password"))
//                .roles(ApplicationUserRole.STUDENT.name())
               .authorities(ApplicationUserRole.STUDENT.getGrantedAuthorities())
                .build(); // without this build method typr of pepperUser is User.UserBuilder

        UserDetails kellyUser = User.builder()
                .username("kelly")
                .password(passwordEncoder.encode("password1"))
//                .roles(ApplicationUserRole.ADMIN.name())
                .authorities(ApplicationUserRole.ADMIN.getGrantedAuthorities())
                .build(); // without this build method type of pepperUser is User.UserBuilder

        UserDetails tomUser = User.builder()
                .username("tom")
                .password(passwordEncoder.encode("password2"))
                .authorities(ApplicationUserRole.ADMINTRAINEE.getGrantedAuthorities())
//                .roles(ApplicationUserRole.ADMINTRAINEE.name())
                .build();

        return new InMemoryUserDetailsManager(
                pepperUser,
                kellyUser,
                tomUser
        );
    }
}
