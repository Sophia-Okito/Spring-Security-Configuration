package com.example.springsecurity.exceptions;

public class UnathorizedException extends RuntimeException {

    public UnathorizedException(String message) {
        super(message);
    }
}
