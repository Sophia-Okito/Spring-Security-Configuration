package com.example.springsecurity.configurations.security;

import com.example.springsecurity.enums.AuthProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.HashSet;

public class CustomAuthenticationToken implements Authentication {

    private final String id;

    private final String password;

    private final AuthProvider authProvider;

    public CustomAuthenticationToken(String id, String password, AuthProvider authProvider) {
        this.id = id;
        this.password = password;
        this.authProvider = authProvider;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        return new HashSet<SimpleGrantedAuthority>();
    }

    public String getPassword() {
        return password;
    }

    @Override
    public Object getCredentials() {
        return this.id;
    }

    public AuthProvider getAuthProvider() {
        return authProvider;
    }

    @Override
    public Object getDetails() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return null;
    }

    @Override
    public boolean isAuthenticated() {
        return false;
    }

    @Override
    public void setAuthenticated(boolean b) throws IllegalArgumentException {

    }

    @Override
    public String getName() {
        return null;
    }

}
