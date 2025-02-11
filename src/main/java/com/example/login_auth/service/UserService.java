package com.example.login_auth.service;

import com.example.login_auth.domain.User;
import com.example.login_auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {
    private final UserRepository userRepository;

    public void create(User user){
        this.userRepository.save(user);
    }

    public User findUserByEmail(String userEmail){
        return this.userRepository.findByEmail(userEmail).orElseThrow(() -> new RuntimeException("User not found"));
    }
}
