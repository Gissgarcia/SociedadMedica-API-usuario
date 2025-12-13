package com.sociedadmedica.usuario.model;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class ForgotPasswordRequest {

    @Email(message = "Debe ser un correo electrónico válido.")
    @NotBlank(message = "Debe ingresar un correo.")
    private String email;
}
