package com.sociedadmedica.usuario.model;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ResetPasswordRequest {

    @NotBlank(message = "Debe ingresar el token.")
    private String token;

    @NotBlank(message = "Debe ingresar una nueva contraseña.")
    @Size(min = 6, message = "La contraseña debe tener al menos 6 caracteres.")
    private String newPassword;
}
