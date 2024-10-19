package com.example.springsecurity.configurations.security;

import com.example.springsecurity.configurations.security.jwt.UserModelDetailsService;
import com.example.springsecurity.enums.AuthProvider;
import com.example.springsecurity.exceptions.BadRequestException;
import com.example.springsecurity.models.User;
import com.example.springsecurity.repositories.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
@RequiredArgsConstructor
public class CustomAuthenticationProvider implements AuthenticationProvider {

    private final UserModelDetailsService userModelDetailsService;

    private final UserRepository userRepository;



    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        CustomAuthenticationToken authenticationToken = (CustomAuthenticationToken) authentication;
        String principal = authenticationToken.getCredentials().toString();
        String password = authenticationToken.getPassword() == null ? "" : authenticationToken.getPassword();
        if (authenticationToken.getAuthProvider() == AuthProvider.activation) {
            return userEmailAuthentication(principal);
        }

        return userEmailAndPasswordAuthentication(principal, password);

    }

    private Authentication userEmailAuthentication(String principal) {
        User user = userRepository.findFirstByEmail(principal).orElseThrow(() -> new BadRequestException("Authentication failed"));
        List<GrantedAuthority> grantedAuthorities = List.of(new SimpleGrantedAuthority(user.getRole().name()));
        return new UsernamePasswordAuthenticationToken(principal, "password", grantedAuthorities);
    }

    private Authentication userEmailAndPasswordAuthentication(String principal, String password) {
        User user = userRepository.findFirstByEmail(principal).orElseThrow(() -> new BadRequestException("Authentication failed"));
        List<GrantedAuthority> grantedAuthorities = List.of(new SimpleGrantedAuthority(user.getRole().name()));
        DBAuthenticationProvider authenticationProvider = new DBAuthenticationProvider(userModelDetailsService);
        return authenticationProvider.authenticate(new UsernamePasswordAuthenticationToken(principal, password, grantedAuthorities));
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass.equals(CustomAuthenticationToken.class);
    }
}

