package com.example.jwt.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.jwt.entity.User;

public interface UserRepository extends JpaRepository<User, String> {

}
