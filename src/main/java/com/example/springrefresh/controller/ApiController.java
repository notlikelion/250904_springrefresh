package com.example.springrefresh.controller;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ApiController {
    @GetMapping("/api/hello")
    public ResponseEntity<String> hello(@AuthenticationPrincipal User user) {
        System.out.println("ApiController.hello");
        return ResponseEntity.ok("Hello, " + user.getUsername() + ", 당신은 USER 등급입니다.");
    }
}
