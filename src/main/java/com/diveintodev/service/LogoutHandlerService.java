package com.diveintodev.service;

import com.diveintodev.repository.TokenRepo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.stereotype.Service;

@Service
public class LogoutHandlerService implements LogoutHandler {

    @Autowired
    private TokenRepo tokenRepo;

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        String authHeader = request.getHeader("Authorization");
        String token =null;
        if(authHeader != null && authHeader.startsWith("Bearer ")){
            token = authHeader.substring(7);
            var tokenFromDB = tokenRepo.findByToken(token).orElse(null);

            if(tokenFromDB != null){
                tokenFromDB.setExpired(true);
                tokenFromDB.setRevoked(true);

                tokenRepo.save(tokenFromDB);
                SecurityContextHolder.clearContext();
            }

        }

    }
}
