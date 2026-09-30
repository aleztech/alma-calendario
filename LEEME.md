# Calendario privado

La página publicada solo contiene **datos cifrados**. El contenido se descifra en
el navegador con la contraseña; quien abra el código fuente sin ella no ve nada.

- Cifrado: AES-256-GCM
- Clave derivada con PBKDF2-SHA256, 310.000 iteraciones y sal aleatoria por copia
- Una sola contraseña, que da acceso a todo: calendario + hitos + hoja de ruta.
  (El acceso reducido de solo calendario se eliminó.)

## Cambiar el calendario

1. Edita `fuente/calendario.html` (ese fichero no se sube nunca, está en `.gitignore`).
2. Regenera la página:

   ```bash
   node cifrar.js
   ```

   Te pedirá la contraseña. No se guarda en ningún sitio.

   Al terminar comprueba solo el fichero generado contra
   `fuente/palabras-prohibidas.txt` y aborta si algo ha quedado legible.
   Añade a esa lista cualquier nombre propio nuevo que metas en el calendario.

3. Sube:

   ```bash
   git add -A && git commit -m "actualiza calendario" && git push
   ```

## Marcar lo que es privado

Ya no hay copia reducida, así que estos marcadores no tienen efecto (se borran al
cifrar). Se conservan por si algún día vuelve a hacer falta un acceso limitado:

| Dónde  | Apertura            | Cierre               |
|--------|---------------------|----------------------|
| HTML   | `<!-- <<<PRIVADO -->` | `<!-- PRIVADO>>> -->` |
| CSS    | `/* <<<PRIVADO */`  | `/* PRIVADO>>> */`   |
| JS     | `// <<<PRIVADO`     | `// PRIVADO>>>`      |

## Si pierdes `fuente/calendario.html`

Se recupera desde la propia página publicada:

```bash
node cifrar.js --extraer
```

(Hay que volver a poner los marcadores `<<<PRIVADO` a mano después.)

## Elegir contraseña

La página es pública: cualquiera puede descargar el fichero cifrado e intentar
romperlo sin límite de intentos. Las 310.000 iteraciones de PBKDF2 hacen cada
intento lento, pero una contraseña corta o previsible cae igual. Usa cuatro o
cinco palabras sin relación entre ellas. No uses nombres, fechas ni nada
relacionado con la niña.
