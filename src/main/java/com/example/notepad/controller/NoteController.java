package com.example.notepad.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.example.notepad.model.Note;
import com.example.notepad.repository.NoteRepository;

@RestController
@RequestMapping("/notes")
public class NoteController {

    @Autowired
    private NoteRepository repo;

    // CREATE NOTE
    @PostMapping
    public ResponseEntity<?> createNote(@RequestBody Note note, Authentication auth) {
        String username = auth.getName();
        note.setUsername(username);

        Note savedNote = repo.save(note);  // ✅ FIXED

        return ResponseEntity.status(HttpStatus.CREATED).body(savedNote); // ✅ FIXED
    }

    // GET NOTES
    @GetMapping
    public ResponseEntity<?> getNotes(Authentication auth) {
        String username = auth.getName();

        return ResponseEntity.ok(repo.findByUsername(username)); // ✅ OK
    }
}