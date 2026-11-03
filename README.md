# Gestor de contraseÃ±as

Gestor de contraseÃ±as personal con cifrado local. Los datos se guardan cifrados (scrypt + Fernet) y se sincronizan
entre el PC y el mÃ³vil por la red local.

| Carpeta | Contenido |
|---|---|
| [`pc/`](pc) | AplicaciÃ³n de escritorio para Windows (Python + tkinter), cÃ³digo fuente |
| [`extension/`](extension) | ExtensiÃ³n para Chrome, Brave y Edge: guarda y actualiza contraseÃ±as y sugiere contraseÃ±as seguras |
| [`android/`](android) | AplicaciÃ³n de Android (Kotlin + Jetpack Compose), cÃ³digo fuente y [APK](android/apk) |

## Descargas y actualizaciones
El ejecutable de Windows se publica en [Releases](../../releases/latest). La aplicaciÃ³n busca allÃ­ las versiones nuevas:
cada release incluye el exe, `version.json` y `version.sig`. El manifiesto estÃ¡ firmado con Ed25519 y la app solo
instala actualizaciones firmadas con la clave del autor, comprobando ademÃ¡s tamaÃ±o y SHA-256.

## Compilar el PC
Desde la carpeta de trabajo (con `extension` junto a `gestor.py`):
```
python -m PyInstaller --noconfirm --clean --onefile --windowed --icon icon.ico --add-data "icon.ico;." --add-data "extension;extension" --hidden-import PIL.ImageTk --name GestorContraseÃ±as gestor.py
```

## Compilar Android
`gradle :app:assembleRelease` con JDK 17 y el SDK de Android. La firma de release se lee de `keystore.properties`
(no incluido en el repositorio).

Â© BadyX
