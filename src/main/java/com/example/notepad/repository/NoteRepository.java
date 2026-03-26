package com.example.notepad.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import com.example.notepad.model.Note;

public interface NoteRepository extends JpaRepository<Note, Long> {
	
    List<Note> findByUsername(String username);
}