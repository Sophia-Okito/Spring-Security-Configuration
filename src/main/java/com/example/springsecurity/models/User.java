package com.example.springsecurity.models;

import com.example.springsecurity.enums.RoleName;
import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.io.Serializable;
import java.time.LocalDateTime;

@Setter
@Getter
@Entity
@Table(name = "USERS")
public class User extends AbstractAuditingEntity<User> implements Serializable {

   @Id
   @GeneratedValue(strategy = GenerationType.IDENTITY)
   private Long id;

   @JsonIgnore
   private String password;

   private String name;

   private String email;

   @Column(name = "enabled", columnDefinition="BOOLEAN DEFAULT false")
   private boolean enabled;

   @Column(name = "activated", columnDefinition="BOOLEAN DEFAULT false")
   private boolean activated;

   private LocalDateTime lastLoginDate;

   private LocalDateTime lastPasswordResetDate;

   @Enumerated(EnumType.STRING)
   private RoleName role = RoleName.ROLE_USER;



}
