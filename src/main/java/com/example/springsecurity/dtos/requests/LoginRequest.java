package com.example.springsecurity.dtos.requests;

import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
@AllArgsConstructor
@NoArgsConstructor
public class LoginRequest {

   @NotBlank(message = "email is required")
   private String email;

   @NotBlank(message = "password is required")
   private String password;

   private Boolean rememberMe;

}
