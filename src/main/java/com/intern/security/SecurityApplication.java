package com.intern.security;

import com.intern.security.model.Role;
import com.intern.security.model.User;
import com.intern.security.repository.RoleRepository;
import com.intern.security.repository.UserRepository;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.util.HashSet;
import java.util.Set;

@SpringBootApplication
public class SecurityApplication {

	public static void main(String[] args) {
		SpringApplication.run(SecurityApplication.class, args);
	}

	@Bean
	CommandLineRunner run(RoleRepository roleRepository, UserRepository userRepository, PasswordEncoder encoder){
		return args ->
		{
			if(roleRepository.findByAuthority("ADMIN").isPresent()) return;
			Role adminRole = roleRepository.save(new Role(2,"ADMIN"));
			roleRepository.save(new Role(1,"USER"));
			Set<Role> roles = new HashSet<>();
			roles.add(adminRole);
			User user = new User(1,"Theara",encoder.encode("123456"),roles);
			userRepository.save(user);
		};
	}
}
