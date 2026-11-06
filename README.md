# Aula segura

Simulación para una práctica con docentes: qué pasa con las contraseñas cuando roban una base de datos.
Todo es una demo con contraseñas inventadas. No hace falta base de datos: el estado vive en memoria.

## Cómo se usa

- **Docentes:** abren la URL principal (`/`) y entran con la tarjeta que les toque (docente01 a docente15).
- **Instructor (atacante):** abre `/atacante` con la clave de instructor.
  - Botón **Tarjetas**: genera las 15 tarjetas para imprimir (la etiqueta de nivel no se imprime).
  - Selector de método: SHA-256 sin sal, SHA-256 con sal, scrypt con sal.
  - **Iniciar ataque**: en las pantallas de los docentes aparece "Se atacó la plataforma" y al final ven si su contraseña cayó o resistió.
  - **Reiniciar ronda**: borra resultados pero conserva las contraseñas que los docentes cambiaron.
  - **Restaurar cuentas**: vuelve todas las contraseñas a las de las tarjetas (úsalo al terminar).

## Guion sugerido (15 a 20 min)

1. Reparte las tarjetas y pide que entren. Verán cómo guarda la plataforma su contraseña.
2. Ronda 1 con **SHA-256 sin sal**: ataca. Caen las débiles y las medias; resisten las frases largas.
3. Ronda 2 con **scrypt con sal**: ataca otra vez. Las débiles siguen cayendo al instante, las medias resisten solo porque el método es lento.
4. Pide que cambien su contraseña por una frase larga y única, y ataca de nuevo.
5. Cierra con gestores de contraseñas y MFA/passkeys.

## Desplegar en Render

1. Sube esta carpeta a un repositorio de GitHub (`node_modules` ya está en `.gitignore`).
2. En Render: **New > Web Service**, conecta el repo.
3. Runtime: Node. Build command: `npm install`. Start command: `npm start`.
4. En **Environment** agrega `INSTRUCTOR_KEY` con una clave tuya. Sin ella se usa "instructor".
5. Opcional: `SCRYPT_N` (por defecto 4096). Si el plan gratis va lento en el modo scrypt, bájalo a 2048.
6. Cuando termine el deploy, comparte la URL con los docentes y entra tú a `/atacante`.

Notas:
- El plan gratis de Render se duerme tras 15 min sin tráfico y tarda en despertar. Abre la página 5 a 10 minutos antes de la práctica.
- Si el servidor se reinicia, el estado vuelve a cero. Las tarjetas no cambian porque las contraseñas están fijas en `server.js`.
- Supabase no es necesario. Solo tendría sentido si quisieras guardar resultados de varias sesiones.
- Las contraseñas de las tarjetas están en `server.js` (objeto `PASS`). Puedes cambiarlas.
# prueba_Sabado
