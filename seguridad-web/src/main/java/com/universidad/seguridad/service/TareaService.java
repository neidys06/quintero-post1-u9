package com.universidad.seguridad.service;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.repository.TareaRepository;
import com.universidad.seguridad.repository.UsuarioRepository;
import java.util.List;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.parameters.P;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@Transactional(readOnly = true)
public class TareaService {

    private final TareaRepository repo;
    private final UsuarioRepository usuarioRepo;

    public TareaService(TareaRepository repo, UsuarioRepository usuarioRepo) {
        this.repo = repo;
        this.usuarioRepo = usuarioRepo;
    }

    // ADMIN puede ver las de cualquiera; USER solo las suyas. authentication.name
    // es el correo tanto con sesión (Parte 1) como con JWT (Parte 2).
    // @P da nombre explícito al parámetro usado en la expresión SpEL.
    @PreAuthorize("hasRole('ADMIN') or #email == authentication.name")
    public List<Tarea> listarDe(@P("email") String email) {
        return repo.findByPropietarioEmail(email);
    }

    @PreAuthorize("hasRole('ADMIN')")
    public List<Tarea> listarTodas() {
        return repo.findAllConPropietario();
    }

    @PreAuthorize("hasRole('ADMIN') or #email == authentication.name")
    public List<Tarea> buscar(@P("email") String email, String texto) {
        return repo.buscarPorTitulo(email, texto); // @Query parametrizado — seguro
    }

    @Transactional
    @PreAuthorize("#email == authentication.name")
    public Tarea crear(@P("email") String email, Tarea tarea) {
        Usuario propietario = usuarioRepo.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("Usuario no encontrado: " + email));
        tarea.setId(null);
        tarea.setPropietario(propietario);
        tarea.setCompletada(false);
        return repo.save(tarea);
    }

    /** Completa una tarea si pertenece al usuario o si quien la completa es ADMIN. */
    @Transactional
    public void completar(Long id, String email, boolean esAdmin) {
        Tarea tarea = repo.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Tarea no encontrada: " + id));
        if (!esAdmin && !tarea.getPropietario().getEmail().equals(email)) {
            throw new AccessDeniedException("La tarea no le pertenece");
        }
        tarea.setCompletada(true);
    }
}
