# Gestor de contraseñas

Gestor de contraseñas personal con cifrado local. Los datos se guardan cifrados (scrypt + Fernet) y se sincronizan
entre el PC y el móvil por la red local.

| Carpeta | Contenido |
|---|---|
| [`pc/`](pc) | Aplicación de escritorio para Windows (Python + tkinter), código fuente |
| [`extension/`](extension) | Extensión para Chrome, Brave y Edge: guarda y actualiza contraseñas y sugiere contraseñas seguras |
| [`android/`](android) | Aplicación de Android (Kotlin + Jetpack Compose), código fuente y [APK](android/apk) |

## Descargas y actualizaciones
El ejecutable de Windows se publica en [Releases](../../releases/latest). La aplicación busca allí las versiones nuevas:
cada release incluye el exe, `version.json` y `version.sig`. El manifiesto está firmado con Ed25519 y la app solo
instala actualizaciones firmadas con la clave del autor, comprobando además tamaño y SHA-256.

## Compilar el PC
Desde la carpeta de trabajo (con `extension` junto a `gestor.py`):
```
python -m PyInstaller --noconfirm --clean --onefile --windowed --icon icon.ico --add-data "icon.ico;." --add-data "extension;extension" --hidden-import PIL.ImageTk --name GestorContraseñas gestor.py
```

## Compilar Android
`gradle :app:assembleRelease` con JDK 17 y el SDK de Android. La firma de release se lee de `keystore.properties`
(no incluido en el repositorio).

© BadyX
