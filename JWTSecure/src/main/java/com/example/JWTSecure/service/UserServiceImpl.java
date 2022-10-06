package com.example.JWTSecure.service;

import com.example.JWTSecure.domain.Role;
import com.example.JWTSecure.domain.User;
import com.example.JWTSecure.repo.RoleRepo;
import com.example.JWTSecure.repo.UserRepo;
import com.example.JWTSecure.validate.Validate;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import javax.transaction.Transactional;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
@RequiredArgsConstructor
@Transactional
@Slf4j
public class UserServiceImpl implements UserService, UserDetailsService {

    @Autowired
    private UserRepo userRepo;
    @Autowired
    private RoleRepo roleRepo;
    @Autowired
    private final PasswordEncoder passwordEncoder;

    @Override
    public User saveUser(User user) {
        user.setPassword(passwordEncoder.encode(user.getPassword()));
        return userRepo.save(user);
    }

    @Override
    public Role saveRole(Role role) {
        return roleRepo.save(role);
    }

    @Override
    public void addRoleToUser(String username, String rolename) {
        User user = userRepo.findByUserName(username);
        Role role = roleRepo.findByName(rolename);
        user.getRoles().add(role);
    }

    @Override
    public User getUser(String username) {
        return userRepo.findByUserName(username);
    }

    @Override
    public List<User> getUsers() {
        return userRepo.findAll();
    }

    @Override
    public List<Role> getRoles() {
        return roleRepo.findAll();
    }

    @Override
    public User checkLogin(User user) {
        if (userRepo.existsByUserNameAndPassword(user.getUserName(), user.getPassword())) {
            return userRepo.findByAcc(user.getUserName(), user.getPassword());
        }
        return null;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = new User();
        if(Validate.validateEmail(username)){
            user = userRepo.findByEmail(username);
            username = user.getUserName();
        }else{
            user = userRepo.findByUserName(username);
            username = user.getUserName();
        }
        if (user == null) {
            log.error("User not found in the database");
            throw new UsernameNotFoundException("User not found in the database");
        } else {
            log.info("User found in the database: {}", username);
        }
        Collection<SimpleGrantedAuthority> authorities = new ArrayList<>();
        user.getRoles().forEach(role -> {
            authorities.add(new SimpleGrantedAuthority(role.getName()));
        });
        List<String> list = new ArrayList<>();
        list.add(user.getUserName());
        list.add(user.getName());

        Map<String, String> map = new HashMap<>();
        map.put("username", user.getUserName());
        map.put("name", user.getName());
        return new org.springframework.security.core.userdetails.User(map.toString(), user.getPassword(), authorities);
    }
}
