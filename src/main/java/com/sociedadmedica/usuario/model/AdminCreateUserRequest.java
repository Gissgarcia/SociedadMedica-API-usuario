package com.sociedadmedica.usuario.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class AdminCreateUserRequest {

    @NotBlank(message = "Debe ingresar un nombre.")
    @Size(min = 4, max = 50, message = "El nombre debe tener entre 4 y 50 caracteres.")
    private String name;

    @Email(message = "Debe ser un correo electrónico válido.")
    @NotBlank(message = "Debe ingresar un correo.")
    private String email;

    @NotBlank(message = "Debe ingresar una contraseña.")
    @Size(min = 6, message = "La contraseña debe tener al menos 6 caracteres.")
    private String password;

    // ✅ roles permitidos: DOCTOR, RECEPCIONISTA, ADMIN
    private RolUsuario role;
}
