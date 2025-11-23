

@Data
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name="Users")
public class UserEntity{
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank(message = "Debe ingresar un nombre.")
    @Column(unique = true, nullable = false)
    @Size(min = 4, max = 50)
    private String username;

    @NotBlank(message = "Debe ingresar una contraseña.")
    private String password;

    @Email(message = "Debe ser un correo electrónico válido.")
    @NotBlank
    @Column(unique = true, nullable = false)
    private String email;

}
