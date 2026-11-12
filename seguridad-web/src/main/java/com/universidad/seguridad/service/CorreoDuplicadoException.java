package com.universidad.seguridad.service;

/** El correo ya pertenece a otro usuario. */
public class CorreoDuplicadoException extends RuntimeException {

    public CorreoDuplicadoException(String mensaje) {
        super(mensaje);
    }
}
