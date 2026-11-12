package com.universidad.seguridad.dto;

import com.universidad.seguridad.model.Tarea;

/**
 * Lo que la API devuelve de una tarea. No se serializa la entidad directamente
 * para no exponer el Usuario propietario completo (su hash de contraseña).
 */
public record TareaDto(Long id, String titulo, String descripcion, boolean completada, String propietario) {

    public static TareaDto desde(Tarea t) {
        return new TareaDto(t.getId(), t.getTitulo(), t.getDescripcion(),
                t.isCompletada(), t.getPropietario().getEmail());
    }
}
