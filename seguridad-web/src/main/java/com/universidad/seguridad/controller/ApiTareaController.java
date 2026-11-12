package com.universidad.seguridad.controller;

import com.universidad.seguridad.dto.TareaDto;
import com.universidad.seguridad.service.TareaService;
import java.util.List;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** Rutas REST protegidas por JWT. */
@RestController
@RequestMapping("/api")
public class ApiTareaController {

    private final TareaService service;

    public ApiTareaController(TareaService service) {
        this.service = service;
    }

    // GET /api/tareas — tareas del usuario dueño del token
    @GetMapping("/tareas")
    public List<TareaDto> misTareas(Authentication auth) {
        // Authentication llega poblado por JwtAuthFilter, igual que llegaría con
        // sesión: el servicio no necesita saber qué mecanismo autenticó al usuario
        return service.listarDe(auth.getName()).stream().map(TareaDto::desde).toList();
    }

    // GET /api/admin/tareas — todas las tareas; solo un token con ROLE_ADMIN
    @GetMapping("/admin/tareas")
    public List<TareaDto> todas() {
        return service.listarTodas().stream().map(TareaDto::desde).toList();
    }
}
