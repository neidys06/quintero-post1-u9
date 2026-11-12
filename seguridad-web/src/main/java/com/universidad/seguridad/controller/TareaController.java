package com.universidad.seguridad.controller;

import com.universidad.seguridad.model.Tarea;
import com.universidad.seguridad.service.TareaService;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

/** Acciones sobre tareas desde el dashboard (formularios con token CSRF). */
@Controller
@RequestMapping("/tareas")
public class TareaController {

    private final TareaService service;

    public TareaController(TareaService service) {
        this.service = service;
    }

    @PostMapping
    public String crear(@RequestParam String titulo,
                        @RequestParam(required = false) String descripcion,
                        Authentication auth, RedirectAttributes flash) {
        if (titulo == null || titulo.isBlank() || titulo.length() > 150) {
            flash.addFlashAttribute("error", "El título es obligatorio (máximo 150 caracteres).");
            return "redirect:/dashboard";
        }
        Tarea tarea = new Tarea();
        tarea.setTitulo(titulo.trim());
        tarea.setDescripcion(descripcion);
        service.crear(auth.getName(), tarea);
        flash.addFlashAttribute("mensaje", "Tarea creada.");
        return "redirect:/dashboard";
    }

    // Búsqueda por título: el texto llega tal cual a un @Query parametrizado
    @GetMapping("/buscar")
    public String buscar(@RequestParam String texto, Authentication auth, RedirectAttributes flash) {
        flash.addFlashAttribute("tareas", service.buscar(auth.getName(), texto));
        flash.addFlashAttribute("busqueda", texto);
        return "redirect:/dashboard";
    }

    @PostMapping("/{id}/completar")
    public String completar(@PathVariable Long id, Authentication auth) {
        boolean esAdmin = auth.getAuthorities().stream()
                .anyMatch(a -> "ROLE_ADMIN".equals(a.getAuthority()));
        service.completar(id, auth.getName(), esAdmin);
        return "redirect:/dashboard";
    }
}
