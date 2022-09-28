package com.example.JWTSecure.service;

import com.example.JWTSecure.domain.Role;
import com.example.JWTSecure.domain.User;

import java.util.List;

public interface UserService {
    User saveUser(User user);
    Role saveRole(Role role);
    void addRoleToUser(String username, String rolename);
    User getUser(String username);
    List<User> getUsers();
    List<Role> getRoles();
    User checkLogin(User user);
}
