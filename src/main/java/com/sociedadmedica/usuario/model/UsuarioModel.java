package com.sociedadmedica.usuario.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.time.Instant;
import java.util.Collection;
import java.util.List;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "Usuario")
@Builder
public class UsuarioModel implements UserDetails {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    /**
     * OJO: este campo en tu app es el "nombre" de la persona.
     * Spring Security NO usará este campo como username porque abajo devolvemos email en getUsername().
     */
    @NotBlank(message = "Debe ingresar un nombre.")
    @Column(nullable = false)
    @Size(min = 4, max = 50)
    private String username;

    @NotBlank(message = "Debe ingresar una contraseña.")
    @Column(nullable = false)
    private String password;

    @Email(message = "Debe ser un correo electrónico válido.")
    @NotBlank
    @Column(unique = true, nullable = false)
    private String email;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false)
    private RolUsuario role;

    @Column(nullable = false)
    private boolean enabled = true;

    /**
     * Recuperación de contraseña (Forgot/Reset)
     * Guardamos el HASH del token (nunca el token en claro) + expiración.
     */
    @Column(name = "reset_token_hash")
    private String resetTokenHash;

    @Column(name = "reset_token_expiry")
    private Instant resetTokenExpiry;

    /**
     * Esto es para TU APP (mostrar nombre real).
     * Evita el error de usar getUsername() (que devuelve el email por seguridad).
     */
    @Transient
    public String getDisplayName() {
        return this.username;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + role.name()));
    }

    /**
     * Username para Spring Security (login / autenticación):
     * aquí usas email, lo cual está perfecto.
     */
    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return enabled; }
}
