package com.example.springsecurity.dtos.requests;

import jakarta.validation.constraints.NotBlank;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class BaseRequest {

    @NotBlank(message = "email not found")
    private String email;
}
