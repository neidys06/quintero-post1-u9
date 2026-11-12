package com.universidad.seguridad.controller;

import com.universidad.seguridad.model.Usuario;
import com.universidad.seguridad.service.CorreoDuplicadoException;
import com.universidad.seguridad.service.TareaService;
import com.universidad.seguridad.service.UsuarioService;
import jakarta.validation.Valid;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;

/** Login, registro, dashboard y panel de administración (vistas con sesión). */
@Controller
public class AuthController {

    private final UsuarioService usuarioService;
    private final TareaService tareaService;

    public AuthController(UsuarioService usuarioService, TareaService tareaService) {
        this.usuarioService = usuarioService;
        this.tareaService = tareaService;
    }

    @GetMapping("/")
    public String inicio() {
        return "redirect:/dashboard";
    }

    @GetMapping("/login")
    public String mostrarLogin() {
        return "auth/login";
    }

    @GetMapping("/registro")
    public String mostrarRegistro(Model model) {
        model.addAttribute("usuario", new Usuario());
        return "auth/registro";
    }

    @PostMapping("/registro")
    public String registrar(@Valid @ModelAttribute Usuario usuario, BindingResult result) {
        if (result.hasErrors()) {
            return "auth/registro";
        }
        try {
            usuarioService.registrar(usuario);
            return "redirect:/login?registrado";
        } catch (CorreoDuplicadoException e) {
            result.rejectValue("email", "error.email", e.getMessage());
            return "auth/registro";
        }
    }

    @GetMapping("/dashboard")
    public String dashboard(Model model, Authentication auth) {
        Usuario actual = usuarioService.buscarPorEmail(auth.getName());
        // "nombre" lo escribió el propio usuario al registrarse: es dato NO confiable
        // y la vista lo muestra con th:text (escapado)
        model.addAttribute("nombre", actual.getNombre());
        model.addAttribute("email", actual.getEmail());
        model.addAttribute("roles", auth.getAuthorities());
        if (!model.containsAttribute("tareas")) {
            model.addAttribute("tareas", tareaService.listarDe(auth.getName()));
        }
        return "dashboard";
    }

    @GetMapping("/admin")
    public String adminPanel(Model model) {
        model.addAttribute("usuarios", usuarioService.listarTodos());
        model.addAttribute("tareas", tareaService.listarTodas());
        return "admin/panel";
    }

    // @RequestMapping (todos los métodos) y no @GetMapping: Spring Security hace un
    // forward a esta ruta conservando el método original; si la petición rechazada
    // era un POST (p. ej. /logout sin token CSRF), un @GetMapping respondería 405 en
    // lugar del 403 que fijó el AccessDeniedHandler.
    @RequestMapping("/acceso-denegado")
    public String accesoDenegado() {
        return "error/403";
    }
}
