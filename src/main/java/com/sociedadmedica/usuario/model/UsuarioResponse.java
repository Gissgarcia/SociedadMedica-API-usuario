package com.sociedadmedica.usuario.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class UsuarioResponse {
    private String token;
    private Long userId;
    private String name;
    private String email;
    private RolUsuario role;
}
