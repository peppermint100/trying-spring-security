package com.tutorial.springsecurity.auth;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.annotation.Resource;

@Service
public class ApplicationUserService implements UserDetailsService {

//    @Autowired
    @Resource(name = "fake")
    private final ApplicationUserDao applicationUserDao;

    public ApplicationUserService(ApplicationUserDao applicationUserDao) {
        this.applicationUserDao = applicationUserDao;
    }

    @Override
    public UserDetails loadUserByUsername(String s) throws UsernameNotFoundException {
        return applicationUserDao.selectApplicationUserByUsername(s)
                .orElseThrow(() -> new UsernameNotFoundException(String.format("Username %s is not found", s)));
    }
}
