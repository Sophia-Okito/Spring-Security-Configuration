package com.example.springsecurity.services;


import com.example.springsecurity.dtos.requests.BaseRequest;
import com.example.springsecurity.dtos.requests.LoginRequest;
import com.example.springsecurity.dtos.requests.RegistrationRequest;
import com.example.springsecurity.dtos.responses.ApiResponse;
import com.example.springsecurity.dtos.responses.LoginResponse;
import org.springframework.http.ResponseEntity;

public interface UserService {
    ResponseEntity<ApiResponse> register(RegistrationRequest dto);

    ResponseEntity<ApiResponse> resendCode(BaseRequest baseRequest);

    ResponseEntity<ApiResponse<LoginResponse>> activate(String otp, BaseRequest baseRequest);

    ResponseEntity<ApiResponse<LoginResponse>> login(LoginRequest dto);

}
