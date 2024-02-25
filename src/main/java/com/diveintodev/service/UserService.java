package com.diveintodev.service;

import com.diveintodev.dto.AuthResponse;
import com.diveintodev.entity.Token;
import com.diveintodev.entity.User;
import com.diveintodev.repository.TokenRepo;
import com.diveintodev.repository.UserRepo;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.AllArgsConstructor;
import lombok.NoArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import java.util.List;


/** refresh token and normal token follows the same pattern for token generation **/
@Service
@AllArgsConstructor
@NoArgsConstructor
public class UserService {

    @Autowired
    private PasswordEncoder passwordEncoder;

    private static final String DEFAULT_ROLE ="ROLE_USER";
    private static final String MODERATOR_ROLE ="ROLE_USER,ROLE_MODERATOR";

    @Autowired
    private UserRepo userRepo;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private TokenRepo tokenRepo;

    @Autowired
    private CustomUserDetailsService customUserDetailsService;

    public String addUser(User user){
        if(user != null){
            user.setRoles(DEFAULT_ROLE);
            String encodedPwd = passwordEncoder.encode(user.getPassword());
            user.setPassword(encodedPwd);
            userRepo.save(user);
            return "New user added";
        }
        return "Error adding new user";
    }

    public List<User> getAllUsers() {
        return userRepo.findAll();
    }

    public User getUserById(int userId) {
        return userRepo.findById(userId).get();
    }

    public String addModerator(User user) {
        user.setRoles(MODERATOR_ROLE);
        String encodedPwd = passwordEncoder.encode(user.getPassword());
        user.setPassword(encodedPwd);
        userRepo.save(user);
        return "Moderator added successfully!!!";
    }

    public AuthResponse generateToken(String username) {
        /** First we are going to generate a new token
         * If that token is generated (means not null) -> Then we will invalidate all the tokens in DB,
         * Once all valid tokens are invalidated we will store all those invalidated tokens into the DB
         * After that we will create a token object with our new token and store that new token into the DB
         * in this way there will be only one valid token all the time for a user**/

        String access_token = jwtService.generateToken(username);
        String refresh_token = null;
        if(access_token != null) {
            refresh_token = jwtService.generateRefreshToken(username);
        }

        if(access_token != null){
            User user  = userRepo.findByUsername(username).get();

            List<Token> validUserTokens =tokenRepo.findAllValidUserTokens(user.getId());

            if(!validUserTokens.isEmpty())
            {
                validUserTokens.forEach(t -> {
                    t.setExpired(true);
                    t.setRevoked(true);
                });
                tokenRepo.saveAll(validUserTokens);
            }

            Token tokenObj = new Token();
            tokenObj.setToken(access_token);
            tokenObj.setRevoked(false);
            tokenObj.setExpired(false);
            tokenObj.setUser(user);

            tokenRepo.save(tokenObj);

        }
        return AuthResponse.builder().
                accessToken(access_token)
                .refreshToken(refresh_token)
                .build();
    }

    public AuthResponse generateTokenFromRefreshToken(HttpServletRequest request, HttpServletResponse response) {

        String authHeader = request.getHeader(HttpHeaders.AUTHORIZATION);
        String refresh_token = null;
        String access_token = null;
        String username = null;
        if(authHeader != null && authHeader.startsWith("Bearer ")){
            refresh_token = authHeader.substring(7);
            username = jwtService.extractUserNameFromToken(refresh_token);
        }

        if(username != null){
            UserDetails userDetails = customUserDetailsService.loadUserByUsername(username);

            if(jwtService.isTokenValid(refresh_token,userDetails)){
                access_token = jwtService.generateToken(username);
                System.out.println(access_token);

                if(access_token != null) {
                    User user = userRepo.findByUsername(username).get();
                    List<Token> validUserTokens = tokenRepo.findAllValidUserTokens(user.getId());

                    if(!validUserTokens.isEmpty()) {
                        validUserTokens.forEach(t -> {
                            t.setRevoked(true);
                            t.setExpired(true);
                        });
                        tokenRepo.saveAll(validUserTokens);
                    }

                    Token tokenObj = new Token();
                    tokenObj.setExpired(false);
                    tokenObj.setRevoked(false);
                    tokenObj.setUser(user);
                    tokenObj.setToken(access_token);

                    tokenRepo.save(tokenObj);

                }

            }
        }
        return AuthResponse.builder()
                .refreshToken(refresh_token)
                .accessToken(access_token)
                .build();
    }
}
