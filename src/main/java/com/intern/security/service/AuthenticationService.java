package com.intern.security.service;

import com.intern.security.model.Role;
import com.intern.security.model.User;
import com.intern.security.repository.RoleRepository;
import com.intern.security.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.HashSet;
import java.util.Set;

@Service
@Transactional
@RequiredArgsConstructor
public class AuthenticationService {
    private final UserRepository userRepository;
    private final RoleRepository roleRepository;
    private final PasswordEncoder encoder;
    public User register(String username,String password){
        String encodePassword = encoder.encode(password);
        Role role = roleRepository.findByAuthority("USER").get();
        Set<Role> authorities = new HashSet<>();
        authorities.add(role);
        return userRepository.save(new User(1,username,encodePassword,authorities));
    }
}
