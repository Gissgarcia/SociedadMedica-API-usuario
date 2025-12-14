package com.sociedadmedica.usuario.service;

import com.sociedadmedica.usuario.config.JwtService;
import com.sociedadmedica.usuario.model.*;
import com.sociedadmedica.usuario.repository.UsuarioRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class UsuarioService {

    private final UsuarioRepository usuarioRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public UsuarioResponse register(RegistroRequest request) {

        if (usuarioRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("El correo ya está registrado");
        }

        // ✅ Registro público: SIEMPRE PACIENTE
        RolUsuario role = RolUsuario.PACIENTE;

        UsuarioModel user = UsuarioModel.builder()
                .username(request.getName()) // este campo es el nombre real
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(role)
                .enabled(true)
                .build();

        UsuarioModel saved = usuarioRepository.save(user);

        String token = jwtService.generateToken(saved);

        return UsuarioResponse.builder()
                .token(token)
                .userId(saved.getId())
                .name(saved.getDisplayName()) // ✅ nombre real (no email)
                .email(saved.getEmail())
                .role(saved.getRole())
                .build();
    }

    // =========================
    // LOGIN
    // =========================
    public UsuarioResponse login(LoginRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );

        UsuarioModel user = usuarioRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Usuario no encontrado"));

        String token = jwtService.generateToken(user);

        return UsuarioResponse.builder()
                .token(token)
                .userId(user.getId())
                .name(user.getDisplayName()) // ✅ nombre real
                .email(user.getEmail())
                .role(user.getRole())
                .build();
    }

    // =========================
    // PERFIL: UPDATE (PUT /me)
    // =========================
    public UsuarioResponse updateProfile(UsuarioModel currentUser, UpdateProfileRequest request) {
        if (currentUser == null) throw new RuntimeException("No autenticado");

        // Si cambia email, validar que no exista
        if (!currentUser.getEmail().equalsIgnoreCase(request.getEmail())
                && usuarioRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("El correo ya está registrado");
        }

        currentUser.setUsername(request.getName());
        currentUser.setEmail(request.getEmail());

        UsuarioModel saved = usuarioRepository.save(currentUser);

        return UsuarioResponse.builder()
                .token(null) // no es necesario regenerar token (puedes hacerlo si quieres)
                .userId(saved.getId())
                .name(saved.getDisplayName())
                .email(saved.getEmail())
                .role(saved.getRole())
                .build();
    }

    // =========================
    // RECUPERACIÓN CONTRASEÑA
    // =========================

    private String sha256Base64(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(input.getBytes(StandardCharsets.UTF_8));
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            throw new RuntimeException("Error generando hash", e);
        }
    }

    /**
     * POST /api/usuario/password/forgot
     * Genera token y lo devuelve (modo demo académico).
     * En producción: se enviaría por correo.
     */
    public SimpleMessageResponse forgotPassword(ForgotPasswordRequest request) {
        UsuarioModel user = usuarioRepository.findByEmail(request.getEmail())
                .orElseThrow(() -> new RuntimeException("Si el correo existe, se enviará un enlace"));

        String rawToken = UUID.randomUUID().toString();
        String tokenHash = sha256Base64(rawToken);

        user.setResetTokenHash(tokenHash);
        user.setResetTokenExpiry(Instant.now().plusSeconds(15 * 60)); // 15 min
        usuarioRepository.save(user);

        return SimpleMessageResponse.builder()
                .message("Token de recuperación generado (demo).")
                .token(rawToken) // ✅ para defensa/rúbrica
                .build();
    }

    /**
     * POST /api/usuario/password/reset
     * Cambia contraseña validando token y expiración.
     */
    public SimpleMessageResponse resetPassword(ResetPasswordRequest request) {
        String tokenHash = sha256Base64(request.getToken());

        UsuarioModel user = usuarioRepository.findByResetTokenHash(tokenHash)
                .orElseThrow(() -> new RuntimeException("Token inválido"));

        if (user.getResetTokenExpiry() == null || Instant.now().isAfter(user.getResetTokenExpiry())) {
            throw new RuntimeException("Token expirado");
        }

        user.setPassword(passwordEncoder.encode(request.getNewPassword()));
        user.setResetTokenHash(null);
        user.setResetTokenExpiry(null);

        usuarioRepository.save(user);

        return SimpleMessageResponse.builder()
                .message("Contraseña actualizada correctamente.")
                .token(null)
                .build();
    }

    public UsuarioResponse adminCreateUser(AdminCreateUserRequest request) {

        if (usuarioRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("El correo ya está registrado");
        }

        // ✅ validar rol (ADMIN decide pero no puede crear PACIENTE por este endpoint)
        RolUsuario role = request.getRole();
        if (role == null) {
            throw new RuntimeException("Debe indicar un rol");
        }

        if (role == RolUsuario.PACIENTE) {
            throw new RuntimeException("Este endpoint es solo para crear DOCTOR, RECEPCIONISTA o ADMIN");
        }

        UsuarioModel user = UsuarioModel.builder()
                .username(request.getName())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(role)
                .enabled(true)
                .build();

        UsuarioModel saved = usuarioRepository.save(user);

        // opcional: podrías devolver token, pero en admin-create normalmente no se entrega token
        return UsuarioResponse.builder()
                .token(null)
                .userId(saved.getId())
                .name(saved.getDisplayName())
                .email(saved.getEmail())
                .role(saved.getRole())
                .build();
    }

}
