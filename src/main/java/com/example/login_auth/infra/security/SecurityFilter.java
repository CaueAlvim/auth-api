package com.example.login_auth.infra.security;

import com.example.login_auth.domain.User;
import com.example.login_auth.infra.security.JWTokenService;
import com.example.login_auth.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

// Filter that executes once after every user request
// verifying if the user is allowed to do that request
@Component
public class SecurityFilter extends OncePerRequestFilter {
    @Autowired
    JWTokenService tokenService;
    @Autowired
    UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        var token = this.recoverToken(request);
        var login = this.tokenService.validateToken(token); // returns user email

        if(login != null){
            User user = userRepository.findByEmail(login).orElseThrow(() -> new RuntimeException("User Not Found"));
            var authorities = Collections.singletonList(new SimpleGrantedAuthority("ROLE_USER")); // Create user roles
            var authentication = new UsernamePasswordAuthenticationToken(user, null, authorities); // Create user with their roles
            SecurityContextHolder.getContext().setAuthentication(authentication); // Spring security context
        }
        filterChain.doFilter(request, response);
    }

    // Method receives request and grabs the token,
    // In this case its in the Authorization header,
    // Should you change the location of the token e.g to the body or other header,
    // This method needs to be changed,
    private String recoverToken(HttpServletRequest request){
        var authHeader = request.getHeader("Authorization");
        if(authHeader == null) return null;
        return authHeader.replace("Bearer ", "");
    }
}