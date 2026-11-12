#!/usr/bin/env bash
# Flujo completo de la Parte 2 con curl (ejecutar con la aplicación corriendo).
# En Windows: desde Git Bash. Requiere ADMIN_PASSWORD si se cambió la clave por defecto.
BASE=${BASE:-http://localhost:8080}
CLAVE=${ADMIN_PASSWORD:-admin123}

echo "== 1. Login JWT (200 + token) =="
RESP=$(curl -s -X POST "$BASE/api/auth/login" -H "Content-Type: application/json" \
  -d "{\"email\":\"admin@universidad.edu\",\"contrasenia\":\"$CLAVE\"}")
echo "$RESP"; echo
TOKEN=$(echo "$RESP" | sed -E 's/.*"token":"([^"]+)".*/\1/')

echo "== 1b. Login con contraseña incorrecta (401, sin token) =="
curl -s -i -X POST "$BASE/api/auth/login" -H "Content-Type: application/json" \
  -d '{"email":"admin@universidad.edu","contrasenia":"incorrecta"}'; echo; echo

echo "== 2. GET /api/tareas con Bearer token (200) =="
curl -s -i "$BASE/api/tareas" -H "Authorization: Bearer $TOKEN"; echo; echo

echo "== 3. GET /api/tareas sin token (401) =="
curl -s -i "$BASE/api/tareas"; echo; echo

echo "== 4. GET /api/tareas con token alterado (401) =="
ALTERADO="${TOKEN%?}X"
curl -s -i "$BASE/api/tareas" -H "Authorization: Bearer $ALTERADO"; echo; echo

echo "== 5. POST /logout sin token CSRF (403, cadena de sesión) =="
curl -s -i -X POST "$BASE/logout"; echo
