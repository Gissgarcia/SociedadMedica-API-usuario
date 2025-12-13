package com.sociedadmedica.usuario.model;

import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class SimpleMessageResponse {
    private String message;
    private String token; // demo académico: se devuelve aquí (en prod se envía por correo)
}