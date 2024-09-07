package com.example.springsecurity.exceptions;

import com.example.springsecurity.dtos.responses.ApiResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.validation.BindingResult;
import org.springframework.validation.FieldError;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.context.request.WebRequest;
import org.springframework.web.servlet.mvc.method.annotation.ResponseEntityExceptionHandler;

import java.util.Optional;


@RestControllerAdvice
@Slf4j
public class GenericControllerAdvice extends ResponseEntityExceptionHandler {


    @ExceptionHandler(value = { NotFoundException.class })
    protected ResponseEntity<Object> handleNotFound(RuntimeException ex, WebRequest request) {
        return handleExceptionInternal(ex , new ApiResponse(false,  ex.getMessage()), new HttpHeaders(), HttpStatus.NOT_FOUND, request);
    }

    @ExceptionHandler(value = { BadRequestException.class, InterruptedException.class })
    protected ResponseEntity<Object> handleBadRequest(RuntimeException ex, WebRequest request) {
        return handleExceptionInternal(ex , new ApiResponse(false,  ex.getMessage()), new HttpHeaders(), HttpStatus.BAD_REQUEST, request);
    }

    @ExceptionHandler(value = { UnknownException.class , Exception.class, RuntimeException.class})
    protected ResponseEntity<Object> handleUnknownException(RuntimeException ex, WebRequest request) {
        return handleExceptionInternal(ex, new ApiResponse(false,  ex.getMessage()), new HttpHeaders(), HttpStatus.INTERNAL_SERVER_ERROR, request);
    }

    @ExceptionHandler(value = { UnathorizedException.class, AuthenticationException.class})
    protected ResponseEntity<Object> handleUnauthorizedException(RuntimeException ex, WebRequest request) {
        return handleExceptionInternal(ex, new ApiResponse(false,  ex.getMessage()), new HttpHeaders(), HttpStatus.UNAUTHORIZED, request);
    }

    @ExceptionHandler(value = { AccessDeniedException.class, ForbiddenException.class})
    protected ResponseEntity<Object> handleForbiddenException(RuntimeException ex, WebRequest request) {
        return handleExceptionInternal(ex, new ApiResponse(false,  ex.getMessage()), new HttpHeaders(), HttpStatus.FORBIDDEN, request);
    }


    @ExceptionHandler(value = { PreConditionFailedException.class})
    protected ResponseEntity<Object> handlePreConditionFailedException(RuntimeException ex, WebRequest request) {
        return handleExceptionInternal(ex , new ApiResponse(false,  ex.getMessage()), new HttpHeaders(), HttpStatus.PRECONDITION_FAILED, request);
    }

    @Override
    protected ResponseEntity<Object> handleMethodArgumentNotValid(MethodArgumentNotValidException ex, HttpHeaders headers, HttpStatusCode status, WebRequest request) {
        BindingResult bindingResult = ex.getBindingResult();

        Optional<FieldError> error = bindingResult.getFieldErrors().stream().findFirst();
        String message = "bad request";
        if (error.isPresent()) {
            message = error.get().getDefaultMessage();
        }

        return new ResponseEntity<>(new ApiResponse<>(false, message), HttpStatus.BAD_REQUEST);
    }


}