package com.example.notepad.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.example.notepad.model.User;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByUsername(String username);
}