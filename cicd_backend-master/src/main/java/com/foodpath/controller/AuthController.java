package com.foodpath.controller;

import com.foodpath.payload.request.LoginRequest;
import com.foodpath.payload.request.SignupRequest;
import com.foodpath.payload.response.MessageResponse;
import com.foodpath.service.UserService;
import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@CrossOrigin(origins = "http://localhost:3000", maxAge = 3600, allowCredentials = "true")
@RestController
@RequestMapping("/api/auth")
public class AuthController {
    @Autowired
    UserService userService;

    @PostMapping("/signin")
    public ResponseEntity<?> authenticateUser(@Valid @RequestBody LoginRequest loginRequest) {
        return userService.authenticateUser(loginRequest);
    }

    @PostMapping("/signup")
    public ResponseEntity<?> registerUser(@Valid @RequestBody SignupRequest signUpRequest) {
        return userService.registerUser(signUpRequest);
    }
    
    @GetMapping("/test")
    public ResponseEntity<?> testConnection() {
        return ResponseEntity.ok(new MessageResponse("Backend connection successful"));
    }
}
