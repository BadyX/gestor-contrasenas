# Gestor de contraseñas

Gestor de contraseñas personal con interfaz de escritorio (Python/tkinter), app de Android (Kotlin) y extensión
para Chrome, Brave y Edge. Los datos se guardan cifrados en local (scrypt + Fernet) y se sincronizan por la red local.

## Actualizaciones
La aplicación busca nuevas versiones en las *Releases* de este repositorio. Cada versión publica el ejecutable,
`version.json` y `version.sig`: el manifiesto está firmado con Ed25519 y la app solo instala actualizaciones firmadas
con la clave privada del autor, comprobando además tamaño y SHA-256.

## Compilar
```
python -m PyInstaller --noconfirm --clean --onefile --windowed --icon icon.ico --add-data "icon.ico;." --add-data "extension;extension" --hidden-import PIL.ImageTk --name GestorContraseñas gestor.py
```

© BadyX
