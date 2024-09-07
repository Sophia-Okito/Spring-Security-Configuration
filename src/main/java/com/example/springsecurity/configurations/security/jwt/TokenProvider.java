package com.example.springsecurity.configurations.security.jwt;

import com.example.springsecurity.exceptions.NotFoundException;
import com.example.springsecurity.models.User;
import com.example.springsecurity.repositories.UserRepository;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Optional;
import java.util.stream.Collectors;

@Component
public class TokenProvider implements InitializingBean {

   private final Logger log = LoggerFactory.getLogger(TokenProvider.class);

   private static final String AUTHORITIES_KEY = "auth";

   @Value("${jwt.token-validity-in-seconds}")
   private long tokenValidityInMilliseconds;

   @Value("${jwt.token-validity-in-seconds-for-remember-me}")
   private long tokenValidityInMillisecondsForRememberMe;
   private final UserRepository userRepository;

   private String email;

   private Key key;

   @Value("${jwt.base64-secret}")
   private String base64Secret;


   public TokenProvider(UserRepository userRepository) {
      this.tokenValidityInMilliseconds *=  1000;
      this.tokenValidityInMillisecondsForRememberMe *= 1000;
      this.userRepository = userRepository;
   }


   @Override
   public void afterPropertiesSet() {
      byte[] keyBytes = Decoders.BASE64.decode(base64Secret);
      this.key = Keys.hmacShaKeyFor(keyBytes);
   }


   public void setEmail(String token) {
      Claims claims = Jwts.parser()
              .setSigningKey(key)
              .parseClaimsJws(token)
              .getBody();
      this.email = claims.getSubject();
   }

   public User getCurrentUser() {
      Optional<User> user = userRepository.findFirstByEmail(this.email);
      if (user.isEmpty()) {
         throw new NotFoundException("User does not exists");
      }
      return user.get();
   }


   public String createToken(Authentication authentication, boolean rememberMe) {
      String authorities = authentication.getAuthorities().stream()
              .map(GrantedAuthority::getAuthority)
              .collect(Collectors.joining(","));

      long now = (new Date()).getTime();
      Date validity;
      if (rememberMe) {
         validity = new Date(now + this.tokenValidityInMillisecondsForRememberMe);
      } else {
         validity = new Date(now + this.tokenValidityInMilliseconds);
      }

      return Jwts.builder()
              .setSubject(authentication.getName())
              .claim(AUTHORITIES_KEY, authorities)
              .signWith(key, SignatureAlgorithm.HS512)
              .setExpiration(validity)
              .compact();
   }

   public Authentication getAuthentication(String token) {
      Claims claims = Jwts.parser()
              .setSigningKey(key)
              .parseClaimsJws(token)
              .getBody();

      Collection<? extends GrantedAuthority> authorities =
              Arrays.stream(claims.get(AUTHORITIES_KEY).toString().split(","))
                      .map(SimpleGrantedAuthority::new)
                      .collect(Collectors.toList());

      org.springframework.security.core.userdetails.User principal = new org.springframework.security.core.userdetails.User(claims.getSubject(), "", authorities);

      return new UsernamePasswordAuthenticationToken(principal, token, authorities);
   }

   public boolean validateToken(String authToken) {
      try {
         Jwts.parser().setSigningKey(key).parseClaimsJws(authToken);
         return true;
      } catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
         log.info("Invalid JWT signature.");
         log.trace("Invalid JWT signature trace: {}", e);
      } catch (ExpiredJwtException e) {
         log.info("Expired JWT token.");
         log.trace("Expired JWT token trace: {}", e);
      } catch (UnsupportedJwtException e) {
         log.info("Unsupported JWT token.");
         log.trace("Unsupported JWT token trace: {}", e);
      } catch (IllegalArgumentException e) {
         log.info("JWT token compact of handler are invalid.");
         log.trace("JWT token compact of handler are invalid trace: {}", e);
      }
      return false;
   }

   public String getEmail() {
      return email;
   }
}
