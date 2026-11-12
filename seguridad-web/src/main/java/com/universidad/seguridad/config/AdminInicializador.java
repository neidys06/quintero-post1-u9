package com.universidad.seguridad.config;

import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.UsuarioRepository;
import com.universidad.seguridad.service.UsuarioService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

/**
 * Crea el usuario ADMIN al arrancar si todavía no existe. Reemplaza el INSERT
 * manual con un hash copiado a mano: la contraseña llega por configuración
 * (variable de entorno ADMIN_PASSWORD) y se hashea con el mismo BCrypt de la app.
 */
@Component
public class AdminInicializador implements CommandLineRunner {

    private static final Logger log = LoggerFactory.getLogger(AdminInicializador.class);

    private final UsuarioRepository repo;
    private final PasswordEncoder encoder;
    private final String emailAdmin;
    private final String claveAdmin;

    public AdminInicializador(UsuarioRepository repo, PasswordEncoder encoder,
                              @Value("${app.admin.email}") String emailAdmin,
                              @Value("${app.admin.password}") String claveAdmin) {
        this.repo = repo;
        this.encoder = encoder;
        this.emailAdmin = emailAdmin;
        this.claveAdmin = claveAdmin;
    }

    @Override
    public void run(String... args) {
        if (repo.existsByEmail(emailAdmin)) {
            return;
        }
        Usuario admin = new Usuario();
        admin.setNombre("Administrador");
        admin.setEmail(emailAdmin);
        admin.setContrasenia(encoder.encode(claveAdmin));
        admin.setRol(UsuarioService.ROL_ADMIN);
        admin.setActivo(true);
        repo.save(admin);
        log.info("Usuario ADMIN inicial creado: {}", emailAdmin);
    }
}
