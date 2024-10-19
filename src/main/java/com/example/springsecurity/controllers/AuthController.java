package com.example.springsecurity.controllers;

import com.example.springsecurity.dtos.requests.BaseRequest;
import com.example.springsecurity.dtos.requests.LoginRequest;
import com.example.springsecurity.dtos.requests.RegistrationRequest;
import com.example.springsecurity.dtos.responses.ApiResponse;
import com.example.springsecurity.dtos.responses.LoginResponse;
import com.example.springsecurity.services.UserService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PatchMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/auth")
@RequiredArgsConstructor
public class AuthController {

   private final UserService userService;
   @PostMapping(value = "/register")
   public ResponseEntity<ApiResponse> register(@RequestBody @Valid RegistrationRequest dto) {
      return userService.register(dto);
   }

   @PostMapping(value = "/resend-code")
   public ResponseEntity<ApiResponse> resendCode(@RequestBody @Valid BaseRequest baseRequest) {
      return userService.resendCode(baseRequest);
   }

   @PatchMapping(value = "/activate/{otp}")
   public ResponseEntity<ApiResponse<LoginResponse>> activate(@PathVariable String otp, @RequestBody @Valid BaseRequest baseRequest) {
      return userService.activate(otp, baseRequest);
   }


   @PostMapping("/login")
   public ResponseEntity<ApiResponse<LoginResponse>> login(@Valid @RequestBody LoginRequest loginRequest) {
      return userService.login(loginRequest);
   }



}
