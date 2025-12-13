package com.sociedadmedica.usuario.controller;

import com.sociedadmedica.usuario.model.*;
import com.sociedadmedica.usuario.service.UsuarioService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/usuario")
@RequiredArgsConstructor
@CrossOrigin(origins = {"http://localhost:5173", "http://localhost:3000"})
public class UsuarioController {

    private final UsuarioService usuarioService;

    // =========================
    // AUTH
    // =========================

    @PostMapping("/registro")
    public UsuarioResponse register(@Valid @RequestBody RegistroRequest request) {
        return usuarioService.register(request);
    }

    @PostMapping("/login")
    public UsuarioResponse login(@Valid @RequestBody LoginRequest request) {
        return usuarioService.login(request);
    }

    // =========================
    // PERFIL
    // =========================

    @GetMapping("/me")
    public UsuarioResponse me(@AuthenticationPrincipal UsuarioModel user) {
        if (user == null) throw new RuntimeException("No autenticado");

        return UsuarioResponse.builder()
                .token(null)
                .userId(user.getId())
                .name(user.getDisplayName()) // ✅ nombre real, no email
                .email(user.getEmail())
                .role(user.getRole())
                .build();
    }

    @PutMapping("/me")
    public UsuarioResponse updateMe(
            @AuthenticationPrincipal UsuarioModel user,
            @Valid @RequestBody UpdateProfileRequest request
    ) {
        return usuarioService.updateProfile(user, request);
    }

    // =========================
    // RECUPERACIÓN CONTRASEÑA
    // =========================

    @PostMapping("/password/forgot")
    public SimpleMessageResponse forgot(@Valid @RequestBody ForgotPasswordRequest request) {
        return usuarioService.forgotPassword(request);
    }

    @PostMapping("/password/reset")
    public SimpleMessageResponse reset(@Valid @RequestBody ResetPasswordRequest request) {
        return usuarioService.resetPassword(request);
    }

    @PostMapping("/admin/crear")
    @PreAuthorize("hasRole('ADMIN')")
    public UsuarioResponse adminCrearUsuario(@Valid @RequestBody AdminCreateUserRequest request) {
        return usuarioService.adminCreateUser(request);
    }

}
