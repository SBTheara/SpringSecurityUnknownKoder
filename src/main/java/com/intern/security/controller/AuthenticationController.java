package com.intern.security.controller;

import com.intern.security.model.RegisterUserDTO;
import com.intern.security.model.User;
import com.intern.security.service.AuthenticationService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/auth")
@RequiredArgsConstructor
public class AuthenticationController {
    private final AuthenticationService authenticationService;
    @PostMapping("/register")
    public User registerUser(@RequestBody RegisterUserDTO body){
        return authenticationService.register(body.getUsername(),body.getPassword());
    }
}
