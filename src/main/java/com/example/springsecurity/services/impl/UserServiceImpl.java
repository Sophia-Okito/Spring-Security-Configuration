package com.example.springsecurity.services.impl;

import com.example.springsecurity.configurations.security.CustomAuthenticationToken;
import com.example.springsecurity.configurations.security.jwt.TokenProvider;
import com.example.springsecurity.dtos.requests.BaseRequest;
import com.example.springsecurity.dtos.requests.LoginRequest;
import com.example.springsecurity.dtos.requests.RegistrationRequest;
import com.example.springsecurity.dtos.responses.ApiResponse;
import com.example.springsecurity.dtos.responses.LoginResponse;
import com.example.springsecurity.enums.AuthProvider;
import com.example.springsecurity.enums.RoleName;
import com.example.springsecurity.exceptions.BadRequestException;
import com.example.springsecurity.exceptions.ForbiddenException;
import com.example.springsecurity.exceptions.NotFoundException;
import com.example.springsecurity.exceptions.PreConditionFailedException;
import com.example.springsecurity.models.User;
import com.example.springsecurity.repositories.UserRepository;
import com.example.springsecurity.services.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.Optional;

@Service
@Transactional
@RequiredArgsConstructor
public class UserServiceImpl implements UserService {

    private final TokenProvider tokenProvider;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;


    @Override
    public ResponseEntity<ApiResponse> register(RegistrationRequest dto) {
        Optional<User> optionalUser = userRepository.findFirstByEmail(dto.getEmail());
        if (optionalUser.isPresent()) {
            throw new BadRequestException("Email already exists");
        }

        User user = createUser(dto);
        //todo: generate otp and send otp
        ApiResponse responseBody = ApiResponse.builder().responseMessage("User created successfully").build();
        return new ResponseEntity<>(responseBody, HttpStatus.CREATED);
    }

    @Override
    public ResponseEntity<ApiResponse> resendCode(BaseRequest baseRequest) {
        //todo: resend otp
        ApiResponse responseBody = ApiResponse.builder().responseMessage("OTP sent successfully").build();
        return new ResponseEntity<>(responseBody, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<ApiResponse<LoginResponse>> activate(String otp, BaseRequest baseRequest) {
        User user = userRepository.findFirstByEmail(baseRequest.getEmail()).orElseThrow(() -> new NotFoundException("User not found"));
        //todo verify otp

        user.setEnabled(true);
        user.setActivated(true);
        user = userRepository.save(user);

        CustomAuthenticationToken authenticationToken = new CustomAuthenticationToken(user.getEmail(), "", AuthProvider.activation);
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String jwt = tokenProvider.createToken(authentication, false);
        ApiResponse<LoginResponse> responseBody = ApiResponse.<LoginResponse>builder()
                .responseMessage("Account activated successfully")
                .responseBody(new LoginResponse(user, jwt))
                .build();
        return new ResponseEntity<>(responseBody, HttpStatus.OK);
    }

    @Override
    public ResponseEntity<ApiResponse<LoginResponse>> login(LoginRequest dto) {

        User user = userRepository.findFirstByEmail(dto.getEmail()).orElseThrow(()->new NotFoundException("User not found"));

        if (!user.isActivated()) {
            throw new PreConditionFailedException("Email not verified");
        }

        if (!user.isEnabled()) {
            throw new ForbiddenException("Account suspended. Please contact support");
        }


        CustomAuthenticationToken authenticationToken = new CustomAuthenticationToken(dto.getEmail(), dto.getPassword(), AuthProvider.local);
        Authentication authentication = authenticationManager.authenticate(authenticationToken);
        SecurityContextHolder.getContext().setAuthentication(authentication);
        boolean rememberMe = dto.getRememberMe() != null && dto.getRememberMe();
        String jwt = tokenProvider.createToken(authentication, rememberMe);

        user.setLastLoginDate(LocalDateTime.now());
        user = userRepository.save(user);
        ApiResponse<LoginResponse> responseBody = ApiResponse.<LoginResponse>builder()
                .responseMessage("Login successful")
                .responseBody(new LoginResponse(user, jwt))
                .build();
        return new ResponseEntity<>(responseBody, HttpStatus.OK);

    }

    private User createUser(RegistrationRequest dto) {
        User user = new User();
        user.setEmail(dto.getEmail().trim());
        user.setName(dto.getName().trim());
        user.setEnabled(false);
        user.setRole(RoleName.ROLE_USER);
        user.setPassword(new BCryptPasswordEncoder().encode(dto.getPassword()));
        user.setActivated(false);
        user =  userRepository.save(user);
        return user;
    }


}
