package com.example.JWTSecure.repo;

import com.example.JWTSecure.domain.Role;
import com.example.JWTSecure.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface UserRepo extends JpaRepository<User, Long> {

    @Query("select u from User u where u.userName = :username and u.password = :password")
    User findByAcc(@Param("username") String username, @Param("password") String password);
    boolean existsByUserNameAndPassword(String username, String password);
    User findByUserName(String user);
    User findByEmail(String Email);
}

