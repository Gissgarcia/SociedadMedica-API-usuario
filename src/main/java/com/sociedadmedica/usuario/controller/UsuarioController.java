package com.sociedadmedica.usuario.controller;
import com.sociedadmedica.usuario.model.LoginRequest;
import com.sociedadmedica.usuario.model.RegistroRequest;
import com.sociedadmedica.usuario.model.UsuarioModel;
import com.sociedadmedica.usuario.model.UsuarioResponse;
import com.sociedadmedica.usuario.service.UsuarioService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/usuario")
@RequiredArgsConstructor
@CrossOrigin
public class UsuarioController {

    private final UsuarioService usuarioService;

    @PostMapping("/registro")
    public UsuarioResponse register(@Valid @RequestBody RegistroRequest request) {
        return usuarioService.register(request);
    }

    @PostMapping("/login")
    public UsuarioResponse login(@Valid @RequestBody LoginRequest request) {
        return usuarioService.login(request);
    }

    @GetMapping("/me")
    public UsuarioResponse me(@AuthenticationPrincipal UsuarioModel user) {
        if (user == null) {
            throw new RuntimeException("No autenticado");
        }

        return UsuarioResponse.builder()
                .token(null)
                .userId(user.getId())
                .name(user.getUsername())
                .email(user.getEmail())
                .role(user.getRole())
                .build();
    }
}