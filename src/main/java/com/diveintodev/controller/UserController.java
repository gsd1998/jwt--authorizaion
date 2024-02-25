package com.diveintodev.controller;

import com.diveintodev.dto.AuthRequest;
import com.diveintodev.dto.AuthResponse;
import com.diveintodev.entity.User;
import com.diveintodev.service.JwtService;
import com.diveintodev.service.UserService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpRequest;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/user")
public class UserController {

    @Autowired
    private UserService userService;

    @Autowired
    private JwtService jwtService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @PostMapping("/addUser")
    public String addUser(@RequestBody  User user){
        return userService.addUser(user);
    }

    @GetMapping("/viewAll")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public List<User> viewAll(){
        return userService.getAllUsers();
    }

    @GetMapping("/{userId}")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public User getUserById(@PathVariable int userId){
        return userService.getUserById(userId);
    }

    @GetMapping("/welcome")
    @PreAuthorize("hasAuthority('ROLE_USER')")
    public String getUserById(){
        return "Welcome!!! This is for testing";
    }

    @PostMapping("/addModerator")
    @PreAuthorize("hasAuthority('ROLE_ADMIN') or hasAuthority('ROLE_MODERATOR')")
    public String addModerator(@RequestBody User user){
        return userService.addModerator(user);
    }

    @PostMapping("/generateToken")
    public AuthResponse generateToken(@RequestBody AuthRequest authRequest){

        Authentication authentication = authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        if(authentication.isAuthenticated()) {
            AuthResponse accessToken = userService.generateToken(authRequest.getUsername());
            return accessToken;
        }else{
            throw new UsernameNotFoundException("invalid user request !");
        }
    }

    /** method to generate refresh token for original token **/
    @PostMapping("/generateRefreshToken")
    public AuthResponse refreshToken(HttpServletRequest request, HttpServletResponse response){
        return userService.generateTokenFromRefreshToken(request, response);
    }
}
