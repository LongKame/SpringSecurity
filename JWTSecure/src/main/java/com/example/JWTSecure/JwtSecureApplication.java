package com.example.JWTSecure;

import com.example.JWTSecure.domain.Role;
import com.example.JWTSecure.domain.User;
import com.example.JWTSecure.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.util.HashSet;

@SpringBootApplication
@EnableJpaRepositories
public class JwtSecureApplication {

	public static void main(String[] args) {
		SpringApplication.run(JwtSecureApplication.class, args);
	}

	@Bean
	BCryptPasswordEncoder bCryptPasswordEncoder() {
		return new BCryptPasswordEncoder();
	}
//		@Bean
//		CommandLineRunner run(UserService userService){
//		return args -> {
//			userService.saveRole(new Role(null,"ROLE_USER"));
//			userService.saveRole(new Role(null,"ROLE_MANAGER"));
//			userService.saveRole(new Role(null,"ROLE_ADMIN"));
//			userService.saveRole(new Role(null,"ROLE_SUPER_ADMIN"));
//
//
//			userService.saveUser(new User(null,"Long Nguyen","LongKame","123456","longgiang@gmail.com",new HashSet<>()));
//			userService.saveUser(new User(null,"Long Thanh","LongSaker","123456","logi@gmail.com",new HashSet<>()));
//
//			userService.addRoleToUser("LongKame","ROLE_USER");
//			userService.addRoleToUser("LongSaker","ROLE_USER");
//			userService.addRoleToUser("LongSaker","ROLE_ADMIN");
//			userService.addRoleToUser("LongKame","ROLE_MANAGER");
//		};
//	}
}
