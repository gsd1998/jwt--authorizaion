package com.diveintodev.service;

import com.diveintodev.entity.User;
import com.diveintodev.repository.UserRepo;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepo userRepo;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        Optional<User> user  = userRepo.findByUsername(username);

        return user.map(CustomUserDetails::new).
                orElseThrow(() -> new UsernameNotFoundException("username : " + username + " not found"));

    }
}
