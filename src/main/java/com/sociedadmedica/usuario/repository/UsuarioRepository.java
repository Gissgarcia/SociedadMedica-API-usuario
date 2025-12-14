package com.sociedadmedica.usuario.repository;

import com.sociedadmedica.usuario.model.UsuarioModel;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface UsuarioRepository extends JpaRepository<UsuarioModel, Long> {

    Optional<UsuarioModel> findByEmail(String email);

    boolean existsByEmail(String email);

    // ✅ necesario para forgot / reset password
    Optional<UsuarioModel> findByResetTokenHash(String resetTokenHash);
}
