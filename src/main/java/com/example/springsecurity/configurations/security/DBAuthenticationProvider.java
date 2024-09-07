package com.example.springsecurity.configurations.security;

import com.berryinkstamp.berrybackendservice.configs.security.jwt.AdminModelDetailsService;
import com.berryinkstamp.berrybackendservice.configs.security.jwt.UserModelDetailsService;
import com.berryinkstamp.berrybackendservice.enums.RoleName;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.Collection;
import java.util.Objects;


@RequiredArgsConstructor
public class DBAuthenticationProvider implements AuthenticationProvider {

    private final UserModelDetailsService userModelDetailsService;

    private final AdminModelDetailsService adminModelDetailsService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        try {
            String name = authentication.getName();
            String pass = authentication.getCredentials().toString();
            Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
            boolean admin = authorities.stream().anyMatch(a -> Objects.equals(a.getAuthority(), RoleName.ROLE_ADMIN.name()) || Objects.equals(a.getAuthority(), RoleName.ROLE_SUPER_ADMIN.name()) || Objects.equals(a.getAuthority(), RoleName.ROLE_MEMBER.name()));

            UserDetails user;
            if (admin) {
                user = adminModelDetailsService.loadUserByUsername(name);
            } else {
                user = userModelDetailsService.loadUserByUsername(name);
            }

            if (new BCryptPasswordEncoder().matches(pass, user.getPassword())) {
                return new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword(), user.getAuthorities());
            }

            throw new BadCredentialsException("Invalid username or password");
        }catch (UsernameNotFoundException usernameNotFoundException){
            throw new BadCredentialsException("Invalid username or password");
        }
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass.equals(UsernamePasswordAuthenticationToken.class);
    }

}

