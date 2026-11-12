package com.universidad.seguridad.service;

import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.UsuarioRepository;
import java.util.List;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UsuarioService {

    public static final String ROL_USER = "ROLE_USER";
    public static final String ROL_ADMIN = "ROLE_ADMIN";

    private final UsuarioRepository repo;
    private final PasswordEncoder encoder;

    public UsuarioService(UsuarioRepository repo, PasswordEncoder encoder) {
        this.repo = repo;
        this.encoder = encoder;
    }

    @Transactional
    public void registrar(Usuario usuario) {
        String email = usuario.getEmail().trim().toLowerCase();
        if (repo.existsByEmail(email)) {
            throw new CorreoDuplicadoException("El correo ya está registrado");
        }
        usuario.setEmail(email);
        usuario.setContrasenia(encoder.encode(usuario.getContrasenia())); // hash BCrypt
        // El rol y el estado los fija el servidor: aunque alguien agregue
        // rol=ROLE_ADMIN al formulario (asignación masiva), se sobrescribe aquí
        usuario.setRol(ROL_USER);
        usuario.setActivo(true);
        repo.save(usuario);
    }

    public Usuario buscarPorEmail(String email) {
        return repo.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado: " + email));
    }

    // Segunda barrera además de la regla /admin/** de HttpSecurity
    @PreAuthorize("hasRole('ADMIN')")
    public List<Usuario> listarTodos() {
        return repo.findAll();
    }
}
