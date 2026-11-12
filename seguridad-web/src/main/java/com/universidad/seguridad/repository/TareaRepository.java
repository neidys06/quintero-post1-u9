package com.universidad.seguridad.repository;

import com.universidad.seguridad.model.Tarea;
import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

@Repository
public interface TareaRepository extends JpaRepository<Tarea, Long> {

    // Tareas de un usuario (con el propietario cargado para mostrarlo)
    @Query("SELECT t FROM Tarea t JOIN FETCH t.propietario p WHERE p.email = :email ORDER BY t.id")
    List<Tarea> findByPropietarioEmail(@Param("email") String email);

    // Todas las tareas (panel de ADMIN)
    @Query("SELECT t FROM Tarea t JOIN FETCH t.propietario ORDER BY t.id")
    List<Tarea> findAllConPropietario();

    // SEGURO: @Query con parámetros nombrados. JPA lo envía como PreparedStatement:
    // el valor de :texto viaja como DATO y nunca se interpreta como JPQL/SQL.
    @Query("SELECT t FROM Tarea t JOIN FETCH t.propietario p "
            + "WHERE p.email = :email AND LOWER(t.titulo) LIKE LOWER(CONCAT('%', :texto, '%')) "
            + "ORDER BY t.id")
    List<Tarea> buscarPorTitulo(@Param("email") String email, @Param("texto") String texto);

    // INSEGURO — NUNCA HACER ESTO (solo referencia en comentario, no se compila):
    // @Query(value = "SELECT * FROM tareas WHERE titulo LIKE '%" + texto + "%'", nativeQuery = true)
    // Si texto = "' OR '1'='1", la condición queda  titulo LIKE '%' OR '1'='1%'  → siempre
    // verdadera, y la consulta devuelve TODAS las tareas de TODOS los usuarios.
}
