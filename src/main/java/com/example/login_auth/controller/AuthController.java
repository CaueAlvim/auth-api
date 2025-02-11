package com.example.login_auth.controller;

import com.example.login_auth.domain.User;
import com.example.login_auth.dto.AuthResponseDTO;
import com.example.login_auth.dto.LoginRequestDTO;
import com.example.login_auth.dto.RegisterRequestDTO;
import com.example.login_auth.infra.security.JWTokenService;
import com.example.login_auth.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor // its the same as @Autowired on all of the 3 dependencies bellow
public class AuthController {
    private final UserService userService;
    private final PasswordEncoder passwordEncoder;
    private final JWTokenService tokenService;

    @PostMapping("/login")
    public ResponseEntity login(@RequestBody LoginRequestDTO body){
        User user = this.userService.findUserByEmail(body.email());

        if(passwordEncoder.matches(body.password(), user.getPassword())) {
            String token = this.tokenService.generateToken(user);
            return ResponseEntity.ok(new AuthResponseDTO(user.getName(), token));
        }
        return ResponseEntity.badRequest().build();
    }


    @PostMapping("/register")
    public ResponseEntity register(@RequestBody RegisterRequestDTO body){
        User user = userService.findUserByEmail(body.email());

        if(user == null) {
            User newUser = new User();
            newUser.setPassword(passwordEncoder.encode(body.password()));
            newUser.setEmail(body.email());
            newUser.setName(body.name());
            this.userService.create(newUser);

            String token = this.tokenService.generateToken(newUser);
            return ResponseEntity.ok(new AuthResponseDTO(newUser.getName(), token));
        }
        return ResponseEntity.badRequest().build();
    }
}
