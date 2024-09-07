package com.example.springsecurity.exceptions;

public class PreConditionFailedException extends RuntimeException {

    public PreConditionFailedException(String message) {
        super(message);
    }
}
