package com.diveintodev.exceptionhandler;


import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.security.SignatureException;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ProblemDetail;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

@RestControllerAdvice
public class CustomExceptionHandler {

    @ExceptionHandler(Exception.class)
    public ProblemDetail SecurityExceptionHandler(Exception ex){

        ProblemDetail problemDetails= null;

        if(ex instanceof BadCredentialsException){
            problemDetails = ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(401), ex.getMessage());
            problemDetails.setProperty("authentication exception reason", "Bad credential exception");
        }

        if(ex instanceof AccessDeniedException){
            problemDetails =  ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403),ex.getMessage());
            problemDetails.setProperty("access denied reason","Authorization failure");
        }

        if(ex instanceof SignatureException){
            problemDetails =  ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403),ex.getMessage());
            problemDetails.setProperty("JWT token signature exception","JWT Token given is not valid");
        }

        if(ex instanceof ExpiredJwtException){
            problemDetails =  ProblemDetail.forStatusAndDetail(HttpStatusCode.valueOf(403),ex.getMessage());
            problemDetails.setProperty("JWT token expired","JWT Token already expired");
        }

        return problemDetails;

    }
}
