import base64
import csv
import hashlib
import hmac
import ipaddress
import json
import math
import os
import platform
import queue
import re
import secrets
import shutil
import socket
import ssl
import string
import sys
import threading
import time
import tkinter as tk
import urllib.error
import uuid
import urllib.request
import webbrowser
import zipfile
from collections import Counter, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
from tkinter import filedialog, messagebox, ttk
from urllib.parse import quote, urlparse

from cryptography import x509
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.x509.oid import NameOID

APP_DIR = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "GestorContrasenas")
VAULT = os.path.join(APP_DIR, "boveda.dat")
MAGIC = b"GCV1"
MAX_BACKUPS = 10
OLD_DAYS = 365
HEAD_H, ROW_H = 28, 72 # lista dibujada en canvas: cabecera y alto de fila
LOCK_OPTIONS = [1, 2, 5, 10, 15, 30, 0]  # minutos; 0 = nunca

THEMES = {
    "dark": dict(BG="#0f1220", PANEL="#171a2e", PANEL2="#1e2240", LINE="#2a2f55", TEXT="#e8eaf6",
                 MUTED="#9096b8", ACCENT="#6c7bff", DANGER="#ff5d73", OK="#3ddc97", WARN="#ffb347",
                 PASSC="#b9c0ff", HOVER="#262b52", ACCENT_H="#8190ff"),
    "light": dict(BG="#e9ecf7", PANEL="#ffffff", PANEL2="#f1f3fb", LINE="#d5d9ee", TEXT="#1b1e3a",
                  MUTED="#646a8f", ACCENT="#5566f0", DANGER="#e0364f", OK="#22b573", WARN="#c77700",
                  PASSC="#4650c8", HOVER="#e4e7f6", ACCENT_H="#6f7df5"),
}
FONT = ("Segoe UI", 11)


def apply_theme(name):
    globals().update(THEMES[name])


apply_theme("dark")

SECTIONS = {
    "correos": {"title": "Correos", "sub": "Cuentas de correo guardadas", "field": "Correo", "icon": "✉"},
    "webs": {"title": "Webs", "sub": "Sitios web guardados", "field": "Web", "icon": "🌐"},
}
SORTS = ["Más recientes", "Más antiguas", "A–Z", "Z–A"]

APP_VERSION = "2.10"

# Historial de cambios (lo más reciente primero): (versión, fecha, título, [novedades])
CHANGELOG = [
    ("2.10", "28/10/2026", "Actualizaciones desde GitHub", [
        "🐙 Las actualizaciones se descargan ahora de las Releases del repositorio de GitHub en lugar del VPS. La firma Ed25519 y la comprobación SHA-256 siguen igual, así que el origen de los archivos no afecta a la seguridad.",
    ]),
    ("2.9", "28/10/2026", "Versión visible", [
        "🏷 El número de versión aparece abajo en el centro, tanto en la pantalla de desbloqueo como dentro de la aplicación.",
    ]),
    ("2.8", "28/10/2026", "Actualizaciones automáticas", [
        "⬆ Al abrir la aplicación se comprueba en tu servidor si hay una versión nueva. Si la hay, aparece un aviso con las novedades y tres opciones: «Actualizar ahora», «Más tarde» u «Omitir esta versión».",
        "🛡 El aviso está firmado digitalmente (Ed25519): la app solo acepta actualizaciones firmadas con tu clave, y antes de instalar comprueba el tamaño y la huella SHA-256 del archivo descargado.",
        "♻ Al instalar, la app se cierra, se sustituye el ejecutable y se reinicia sola. La versión anterior se conserva como «GestorContraseñas.anterior.exe» por si hay que volver atrás.",
        "⚙ En Administrador: «Buscar ahora» y un interruptor para desactivar la búsqueda al abrir.",
    ]),
    ("2.7", "28/10/2026", "Brechas en Webs: solo contraseñas", [
        "❗ En la sección Webs el símbolo rojo de brechas se muestra únicamente para contraseñas expuestas (ya no por correos que aparezcan en una brecha). El contador del botón «❗ Brechas» cuenta lo mismo. En Correos sigue señalando contraseñas y correos.",
    ]),
    ("2.6", "28/10/2026", "Sugerencia de contraseña en el navegador", [
        "🔐 La extensión detecta los formularios de registro y de cambio de contraseña (campos «nueva contraseña», contraseña + confirmación, actual + nueva + repetir, o páginas de «Crear cuenta») y, al pulsar en el campo, muestra un panel con una contraseña segura sugerida de 16 caracteres.",
        "✨ «Usar esta contraseña» rellena la nueva contraseña y su confirmación con el mismo valor (nunca la contraseña actual); «↻» genera otra. Al enviar el formulario, el Gestor te ofrece guardarla como siempre.",
        "🛡 No aparece en formularios de inicio de sesión, desaparece con Esc o al escribir tú mismo, y se genera dentro del navegador (sin depender de que el Gestor esté abierto). Probado en Chrome, Edge y Brave, incluidos formularios en Shadow DOM.",
    ]),
    ("2.5", "28/10/2026", "Duplicadas y fortaleza de cada contraseña", [
        "🧩 Botón «Duplicadas (N)» en Correos y Webs: detecta entradas repetidas (mismo correo; o misma web, sin «www.» ni ruta, y mismo usuario) y abre un cuadro para revisarlas. En cada grupo eliges cuál conservar (por defecto, la más reciente), avisa si tienen contraseñas distintas y puedes fusionar un grupo o todos a la vez.",
        "🔗 Al fusionar se completan los campos vacíos de la entrada conservada (alias, notas), se mantiene la fecha de creación más antigua y se borran las demás (el borrado también llega al móvil).",
        "💪 Junto a cada contraseña de las listas se ve ahora su fortaleza: una barra de 4 tramos de color y el nivel (Débil, Media, Fuerte, Muy fuerte), aunque la contraseña esté oculta.",
    ]),
    ("2.4", "28/10/2026", "Generador de contraseñas", [
        "🎲 Nuevo botón «Generador de contraseñas» en el menú (debajo de Brechas): al pulsarlo crea una contraseña segura de 16 caracteres con el mismo sistema que la sugerencia al añadir, la copia al portapapeles y la muestra con el mensaje «Contraseña copiada».",
        "↻ Desde la misma ventana puedes generar otra (se copia también), volver a copiarla y ver su fortaleza. Se borra del portapapeles a los 30 segundos.",
    ]),
    ("2.3", "26/10/2026", "Accesos denegados en los dos dispositivos", [
        "🔄 Los intentos de acceso fallidos del móvil aparecen también en «Accesos denegados» del PC, y los del PC en la pestaña «Accesos» del móvil, con su contraseña, IP, ubicación, fecha y dispositivo.",
        "📡 Aviso inmediato: cuando alguien falla la contraseña en el móvil, se lo comunica al PC en el momento (si está en la misma red), aunque el móvil siga bloqueado y aunque el PC esté bloqueado; si no hay conexión, se envía en la siguiente sincronización.",
        "🔑 Los dos dispositivos comparten la misma clave del registro, que viaja cifrada con la contraseña maestra al sincronizar. Los intentos propios anteriores se vuelven a cifrar con ella.",
        "🗑 «Borrar registro» en un dispositivo también lo borra en el otro. Cuando llegan intentos del otro dispositivo, el PC avisa con un mensaje y el ⚠ del menú.",
    ]),
    ("2.2", "26/10/2026", "Antifuerza bruta y Accesos denegados", [
        "🛡 Solo 2 intentos para desbloquear (PC y Android), con el contador «Intentos disponibles: N de 2» siempre visible.",
        "⏱ Al fallar los 2 intentos la app se bloquea: 10 minutos la primera vez, 1 día la segunda y un día más cada vez que se repite (2, 3, 4 días…). Al acertar, el contador se reinicia.",
        "🔒 Mientras está bloqueada no admite ninguna contraseña (ni la correcta): muestra «La aplicación está bloqueada» y la cuenta atrás en tiempo real. El bloqueo sobrevive a cerrar y reabrir la app, y atrasar el reloj no lo acorta.",
        "⚠ Aviso de Bloq Mayús activado en el PC (en Android, con teclado físico, o si lo escrito parece todo en mayúsculas).",
        "🚫 Nueva sección «Accesos denegados» (debajo de Brechas; en Android, pestaña «Accesos»): por cada intento fallido guarda la contraseña introducida, la IP (pública y de red local), la ubicación aproximada, la fecha y hora y el tipo de dispositivo. Todo cifrado: se registra sin conocer la contraseña maestra y solo se puede leer con la app desbloqueada.",
        "🔔 Si hubo intentos fallidos mientras no estabas, el menú muestra ⚠ y aparece un aviso al entrar. Botón para borrar el registro.",
        "🔧 Los intentos fallidos hechos antes del primer desbloqueo con esta versión (cuando aún no existe la clave del registro) se guardan protegidos con Windows (PC) o el Keystore (Android) y pasan a cifrado definitivo, con su contraseña, en el primer desbloqueo.",
    ]),
    ("2.1", "26/10/2026", "Comprobar webs", [
        "🌐 Botón «Comprobar webs» en la sección Webs (después del orden): comprueba, en paralelo y sin bloquear la app, si cada web guardada sigue en funcionamiento, con progreso y opción de cancelar.",
        "🔴 Al terminar, el botón muestra cuántas webs ya no están disponibles y sus direcciones se ponen en rojo; al pasar el cursor se ve el motivo (dominio inexistente, tiempo agotado, conexión rechazada, HTTP 404/410 o error 5xx) y cuándo se comprobó.",
        "✅ Una web cuenta como disponible si responde, aunque bloquee a los robots (401, 403, 429…) o tenga un certificado raro. Se omiten las entradas que no son direcciones (p. ej. solo «Netflix»).",
        "💾 El resultado se guarda cifrado en este dispositivo (no se sincroniza con el móvil) y se descarta si cambias la dirección de esa web.",
    ]),
    ("2.0", "26/10/2026", "App de Android y sincronización con el móvil", [
        "📱 App de Android (Kotlin + Jetpack Compose) con Correos y Webs, buscador, ver/copiar/editar/eliminar, generador de contraseñas seguras, alias y notas, ⚠ de contraseña repetida, bloqueo automático al salir y sin capturas de pantalla. APK firmado, listo para instalar.",
        "🔄 Sincronización PC ↔ móvil por la red local, sin servidores externos: HTTPS con certificado propio fijado por huella (va en el QR), código de vinculación de un solo uso que caduca a los 5 minutos y cifrado de extremo a extremo con tu contraseña maestra (misma clave y formato en los dos lados).",
        "🔗 Administrador → «Sincronizar con el móvil»: activar/desactivar, QR de vinculación, enlace para copiar, lista de móviles vinculados con su última sincronización y botón para desvincular.",
        "🧬 Fusión de cambios: cada entrada lleva un identificador y una marca de revisión; si se edita en los dos lados gana lo último, y los borrados se propagan mediante «lápidas». Si no hay conexión, los cambios del móvil se sincronizan al volver a la red.",
        "🛠 Las entradas antiguas reciben su identificador automáticamente al desbloquear (con copia de seguridad previa).",
        "📜 Nueva sección Changelog (esta pantalla).",
    ]),
    ("1.8", "25/10/2026", "Brechas en las listas y detalles", [
        "❗ Símbolo rojo en Correos y Webs para las entradas que aparecen en la sección Brechas (contraseña expuesta o correo en una brecha), con el motivo al pasar el cursor, y botón «❗ Brechas (N)» para mostrar u ocultar todos los símbolos.",
        "🔎 La búsqueda también mira las contraseñas.",
        "↔ Contraseñas muy largas: se recortan con «…» en su columna y se ven completas al pasar el cursor, sin invadir la fecha.",
        "☑ Selección múltiple con casillas (y casilla de «marcar todas las mostradas») para eliminar varias entradas de golpe, con confirmación. Combina con ⚠ Repetidas y con el buscador.",
        "📐 Fechas alineadas verticalmente con la contraseña.",
    ]),
    ("1.7", "25/10/2026", "Extensión para Chrome, Brave y Edge", [
        "🔌 Al registrarte o iniciar sesión en una web, el Gestor comprueba si ya tienes ese correo/usuario guardado: si existe propone actualizar la contraseña; si no, propone guardar la web, el usuario y la contraseña. Pregunta antes de guardar (se puede desactivar).",
        "🛡 Seguridad: servidor solo en 127.0.0.1, exige el origen de la extensión y una clave secreta; la función viene desactivada hasta que se activa en Administrador.",
        "🧩 Detecta formularios clásicos, páginas sin <form>, componentes con Shadow DOM, iframes, accesos en dos pasos y botones que no son de envío (como «Hazte miembro»), ignorando el ojo de «mostrar contraseña».",
        "⏳ Si el Gestor está bloqueado, el aviso espera hasta 10 minutos y se procesa al desbloquearlo.",
    ]),
    ("1.6", "25/10/2026", "Brechas de seguridad", [
        "🛡 Nueva sección Brechas: comprueba contraseñas con Have I Been Pwned (k-anonimato: solo se envían 5 caracteres del hash) y correos con XposedOrNot, con barra de progreso, notificación al terminar, tabla de resultados y doble clic para ir a la entrada.",
        "📅 Comprobación automática opcional al entrar (cada 7 días) y caché cifrada de los correos ya comprobados.",
    ]),
    ("1.5", "25/10/2026", "Rendimiento y filtros", [
        "⚡ Con ~1000 webs la app iba lenta: la lista se dibuja ahora sobre un único canvas (de más de un segundo a ~40 ms) y la búsqueda espera a que dejes de escribir.",
        "⚠ Botón «Repetidas»: muestra solo las entradas con contraseña repetida, agrupadas.",
        "ℹ Textos explicativos al pasar el cursor sobre los iconos de ver, copiar, editar y borrar.",
    ]),
    ("1.4", "25/10/2026", "Proton Pass", [
        "📥 Importar desde Proton Pass (CSV, JSON y ZIP sin cifrar; ignora alias, tarjetas y elementos en la papelera).",
        "📤 Exportar para Proton Pass (CSV con su formato) y detección automática de formatos (Proton, Chrome/Edge o el de esta app).",
    ]),
    ("1.3", "25/10/2026", "Seguridad, comodidad y datos", [
        "🔒 Bloqueo automático por inactividad y botón «Bloquear ahora»; límite de intentos con espera creciente al fallar la contraseña maestra.",
        "💪 Indicador de fortaleza al escribir contraseñas y avisos de contraseñas repetidas y de más de un año sin cambiar.",
        "✏ Editar entradas, alias/usuario y notas opcionales, abrir la web desde la lista, ordenar la lista.",
        "💾 Importar/exportar CSV, restaurar copias y copias automáticas (las últimas 10 versiones).",
        "🌙 Modo claro y oscuro, icono propio y fechas de modificación (CREADO / MODIFICADO).",
    ]),
    ("1.2", "25/10/2026", "Sugerencia de contraseñas y fechas", [
        "🎲 Interruptor «Sugerir contraseña segura» al añadir (16 caracteres aleatorios, con botón «Otra»).",
        "🔍 Buscador en Correos y Webs.",
        "🗓 Fecha de creación de cada entrada.",
    ]),
    ("1.1", "24/10/2026", "Administrador", [
        "⚙ Sección Administrador (pide de nuevo la contraseña maestra): eliminar todos los correos, eliminar todas las webs, cambiar la contraseña maestra, copia de seguridad y, al final, abrir el directorio de datos.",
        "© Firma «BadyX · 24/10/2026» abajo a la derecha y contraseñas ocultas por defecto.",
    ]),
    ("1.0", "24/10/2026", "Primera versión", [
        "🖥 Programa de escritorio ejecutable con secciones Correos y Webs: lista con contraseñas, botón «Añadir» con Aceptar/Cancelar y comprobación de campos vacíos.",
        "🔐 Datos guardados en un archivo cifrado (scrypt + AES/Fernet) protegido por una contraseña maestra.",
    ]),
]


def resource(name):
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, name)


# ---------- Configuración (no sensible: tema, bloqueo, intentos) ----------
def load_cfg():
    cfg = {"theme": "dark", "lock_minutes": 5, "lock_fails": 0, "lock_count": 0, "lock_until": 0, "lock_seen": 0,
           "deny_pub": "", "denied_seen": "",
           "breach_consent": False, "breach_auto": False, "show_breach_marks": True,
           "bridge_enabled": False, "bridge_token": "", "bridge_port": BRIDGE_PORT, "bridge_confirm": True,
           "sync_enabled": False, "sync_port": SYNC_PORT, "sync_devices": [],
           "update_check": True, "update_skip": ""}
    try:
        with open(os.path.join(APP_DIR, "config.json"), encoding="utf-8") as f:
            cfg.update(json.load(f))
    except (OSError, ValueError):
        pass
    if cfg["theme"] not in THEMES:
        cfg["theme"] = "dark"
    return cfg


def save_cfg(cfg):
    try:
        os.makedirs(APP_DIR, exist_ok=True)
        with open(os.path.join(APP_DIR, "config.json"), "w", encoding="utf-8") as f:
            json.dump(cfg, f)
    except OSError:
        pass


# ---------- Almacén cifrado ----------
def backup_dir():
    return os.path.join(APP_DIR, "copias")


class Vault:
    """Guarda los datos cifrados con Fernet (AES-128-CBC + HMAC); la clave sale de la
    contraseña maestra con scrypt. En disco solo hay: MAGIC + salt + token cifrado."""

    def __init__(self):
        # "brechas": caché de correos comprobados y último resultado (cifrado junto al resto)
        # "deleted": lápidas {id: rev} de lo borrado, para que un borrado también se propague al móvil
        # "webcheck": resultado de la última comprobación de webs {id: {ok, why, t}} (solo en este dispositivo)
        self.data = {"correos": [], "webs": [], "brechas": {}, "deleted": {}, "webcheck": {}, "denykey": ""}
        self.salt = b""
        self.key = b""
        self.fernet = None
        self.dirty = False  # hay cambios (p. ej. ids asignados al migrar) pendientes de guardar

    @staticmethod
    def exists():
        return os.path.exists(VAULT)

    def _derive(self, password, salt):
        key = Scrypt(salt=salt, length=32, n=2 ** 15, r=8, p=1).derive(password.encode("utf-8"))
        self.key = key
        return Fernet(base64.urlsafe_b64encode(key))

    def create(self, password):
        self.salt = os.urandom(16)
        self.fernet = self._derive(password, self.salt)
        self.save()

    def verify(self, password):
        """Comprueba la contraseña maestra sin tocar el estado actual."""
        key = Scrypt(salt=self.salt, length=32, n=2 ** 15, r=8, p=1).derive(password.encode("utf-8"))
        return hmac.compare_digest(key, self.key)

    def change_password(self, password):
        self.create(password)  # nueva sal + nueva clave, y se vuelve a cifrar todo

    def unlock(self, password, path=None):
        with open(path or VAULT, "rb") as f:
            blob = f.read()
        if blob[:4] != MAGIC:
            raise ValueError("Archivo de datos no válido")
        self.salt = blob[4:20]
        fernet = self._derive(password, self.salt)
        try:
            raw = fernet.decrypt(blob[20:])
        except InvalidToken:
            return False
        self.fernet = fernet
        loaded = json.loads(raw.decode("utf-8"))
        for k in SECTIONS:
            self.data[k] = loaded.get(k, [])
        b = loaded.get("brechas")
        self.data["brechas"] = b if isinstance(b, dict) else {}
        d = loaded.get("deleted")
        self.data["deleted"] = d if isinstance(d, dict) else {}
        w = loaded.get("webcheck")
        self.data["webcheck"] = w if isinstance(w, dict) else {}
        k = loaded.get("denykey")
        self.data["denykey"] = k if isinstance(k, str) else ""
        self.dirty = self.migrate()
        return True

    def migrate(self):
        """Las entradas anteriores a la sincronización no tienen id ni rev: se les asignan."""
        changed = False
        for sec in SECTIONS:
            for e in self.data[sec]:
                if not e.get("id"):
                    e["id"] = uuid.uuid4().hex
                    changed = True
                if "rev" not in e:
                    e["rev"] = legacy_rev(e)
                    changed = True
        return changed

    # --- sincronización con el móvil ---
    def new_entry(self, data):
        return {**data, "id": uuid.uuid4().hex, "rev": now_rev()}

    def remove(self, sec, ids):
        """Borra entradas dejando una lápida (id + momento) para que el borrado llegue al otro dispositivo."""
        ids = set(ids)
        stamp = now_rev()
        for i in ids:
            self.data["deleted"][i] = stamp
        self.data[sec] = [e for e in self.data[sec] if e["id"] not in ids]

    def sync_snapshot(self):
        return {"correos": self.data["correos"], "webs": self.data["webs"], "deleted": self.data["deleted"]}

    def pack(self, payload):
        """Mismo formato que el archivo de datos: MAGIC + sal + token Fernet (para enviarlo cifrado al móvil)."""
        return MAGIC + self.salt + self.fernet.encrypt(json.dumps(payload).encode("utf-8"))

    def unpack(self, blob):
        """Descifra un paquete del móvil. Lanza InvalidToken si la sal o la clave no coinciden."""
        if blob[:4] != MAGIC or blob[4:20] != self.salt:
            raise InvalidToken()
        return json.loads(self.fernet.decrypt(blob[20:]).decode("utf-8"))

    def apply_merged(self, merged):
        for sec in SECTIONS:
            self.data[sec] = merged[sec]
        self.data["deleted"] = merged["deleted"]
        self.save()

    @staticmethod
    def auto_backup():
        """Antes de sobrescribir, guarda la versión anterior en la carpeta de copias (se conservan las últimas 10)."""
        if not os.path.exists(VAULT):
            return
        os.makedirs(backup_dir(), exist_ok=True)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")[:-3]
        shutil.copy2(VAULT, os.path.join(backup_dir(), f"boveda-{stamp}.dat"))
        old = sorted(f for f in os.listdir(backup_dir()) if f.startswith("boveda-") and f.endswith(".dat"))
        for f in old[:-MAX_BACKUPS]:
            try:
                os.remove(os.path.join(backup_dir(), f))
            except OSError:
                pass

    def save(self):
        os.makedirs(APP_DIR, exist_ok=True)
        token = self.fernet.encrypt(json.dumps(self.data).encode("utf-8"))
        self.auto_backup()
        tmp = VAULT + ".tmp"
        with open(tmp, "wb") as f:
            f.write(MAGIC + self.salt + token)
        os.replace(tmp, VAULT)  # escritura atómica: nunca queda el archivo a medias
        self.dirty = False


# ---------- Utilidades ----------
def now_iso():
    return datetime.now().isoformat(timespec="seconds")


def now_rev():
    """Marca de revisión para sincronizar: UTC con milisegundos (se compara como texto)."""
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def legacy_rev(entry):
    """Revisión de una entrada antigua a partir de su fecha de modificación/creación (hora local)."""
    try:
        ts = entry.get("modified") or entry.get("created")
        return datetime.fromisoformat(ts).astimezone(timezone.utc).isoformat(timespec="milliseconds")
    except (TypeError, ValueError, OSError):
        return ""  # sin fecha: la más antigua posible


TOMBSTONE_DAYS = 180


def merge_data(local, remote):
    """Fusiona dos conjuntos {correos, webs, deleted}. Gana la revisión más reciente de cada id;
    un borrado gana si es igual o más reciente que la entrada. No modifica los originales."""
    deleted = dict(local.get("deleted") or {})
    for i, r in (remote.get("deleted") or {}).items():
        if r > deleted.get(i, ""):
            deleted[i] = r
    limit = (datetime.now(timezone.utc) - timedelta(days=TOMBSTONE_DAYS)).isoformat(timespec="milliseconds")
    deleted = {i: r for i, r in deleted.items() if r >= limit}  # las lápidas muy viejas se descartan
    out = {"deleted": deleted}
    for sec in SECTIONS:
        best = {}
        for e in list(local.get(sec) or []) + list(remote.get(sec) or []):
            i = e.get("id")
            if i and (i not in best or e.get("rev", "") > best[i].get("rev", "")):
                best[i] = e
        out[sec] = [dict(e) for i, e in best.items() if i not in deleted or e.get("rev", "") > deleted[i]]
    return out


def format_date(iso):
    """'2026-10-25T14:30:05' -> '25/10/2026 14:30'. Las entradas antiguas no tienen fecha."""
    try:
        return datetime.fromisoformat(iso).strftime("%d/%m/%Y %H:%M")
    except (TypeError, ValueError):
        return "Sin fecha"


def is_old(entry):
    ref = entry.get("changed") or entry.get("created")
    try:
        return (datetime.now() - datetime.fromisoformat(ref)).days >= OLD_DAYS
    except (TypeError, ValueError):
        return False  # sin fecha no se puede saber


def short(text, n=32):
    return text if len(text) <= n else text[: n - 1] + "…"


def strength_colors():
    """Colores de los niveles de fortaleza 1..4 (según el tema actual)."""
    return ["", DANGER, WARN, "#7ed957", OK]


def find_duplicates(entries, section):
    """Grupos de entradas repetidas: en Correos, el mismo correo; en Webs, la misma web (sin «www.» ni ruta)
    y el mismo usuario (el alias puede ser «usuario (correo)»: basta con compartir alguno de los dos).
    Devuelve listas de las propias entradas (las que tienen 2 o más)."""
    if section == "correos":
        by = {}
        for e in entries:
            by.setdefault(e["user"].strip().lower(), []).append(e)
        return [g for k, g in by.items() if k and len(g) > 1]
    by_host = {}
    for e in entries:
        host = host_of(e["user"])
        if host:
            toks = {t for t in re.split(r"[\s()<>,;]+", e.get("alias", "").lower()) if t} or {""}
            by_host.setdefault(host, []).append((e, toks))
    groups = []
    for items in by_host.values():
        parent = list(range(len(items)))

        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        owner = {}
        for i, (_, toks) in enumerate(items):
            for t in toks:
                if t in owner:
                    parent[find(i)] = find(owner[t])  # comparten usuario o correo: misma cuenta
                else:
                    owner[t] = i
        merged = {}
        for i, (e, _) in enumerate(items):
            merged.setdefault(find(i), []).append(e)
        groups += [g for g in merged.values() if len(g) > 1]
    return groups


def pw_hash(p):
    return hashlib.sha1(p.encode("utf-8")).hexdigest().upper()


def generate_password(length=16):
    """Contraseña aleatoria (módulo secrets) con minúsculas, mayúsculas, números y símbolos."""
    pools = [string.ascii_lowercase, string.ascii_uppercase, string.digits, "!@#$%&*?-_+="]
    chars = [secrets.choice(p) for p in pools]
    allchars = "".join(pools)
    chars += [secrets.choice(allchars) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


COMMON = {"password", "123456", "12345678", "123456789", "qwerty", "abc123", "111111", "contraseña",
          "iloveyou", "admin", "letmein", "welcome", "password1", "qwerty123", "000000", "12345"}


def strength(pw):
    """Devuelve (nivel 0-4, texto). 0 = campo vacío."""
    if not pw:
        return 0, ""
    classes = sum([any(c.islower() for c in pw), any(c.isupper() for c in pw),
                   any(c.isdigit() for c in pw), any(not c.isalnum() for c in pw)])
    pts = (len(pw) >= 8) + (len(pw) >= 12) + (len(pw) >= 16) + (classes >= 3)
    if pw.lower() in COMMON or len(set(pw)) <= 3 or len(pw) < 6:
        pts = 0
    level = max(1, pts)
    return level, ["", "Débil", "Media", "Fuerte", "Muy fuerte"][level]


def open_web(parent, text):
    url = text.strip()
    if "://" not in url:
        url = "https://" + url
    if urlparse(url).scheme not in ("http", "https"):
        messagebox.showwarning("Abrir web", "Solo se pueden abrir direcciones http o https.", parent=parent)
        return
    webbrowser.open(url)


# ---------- Importación / exportación (CSV propio, Chrome/Edge, Proton Pass) ----------
PROTON_FIELDS = ["type", "name", "url", "autofillUrls", "email", "username", "password", "note", "totp",
                 "createTime", "modifyTime", "vault"]


def to_unix(iso):
    try:
        return str(int(datetime.fromisoformat(iso).timestamp()))
    except (TypeError, ValueError):
        return ""


def from_unix(value):
    try:
        return datetime.fromtimestamp(int(float(value))).isoformat(timespec="seconds")
    except (TypeError, ValueError, OverflowError, OSError):
        return ""


def modified_date(create, modify):
    """Fecha de modificación solo si Proton la registra distinta de la de creación."""
    return from_unix(modify) if str(modify or "") != str(create or "") else ""


def proton_alias(username, email):
    if username and email and username != email:
        return f"{username} ({email})"
    return username or email


def proton_row(section, e):
    """Fila en el formato de exportación de Proton Pass (12 columnas)."""
    alias = e.get("alias", "")
    if section == "correos":
        name, url, email, username = e["user"], "", e["user"], alias
    else:
        url = e["user"] if "://" in e["user"] else "https://" + e["user"]
        name = (urlparse(url).netloc or e["user"]).removeprefix("www.")
        email, username = ("", alias) if "@" not in alias else (alias, "")
    return ["login", name, url, "", email, username, e["pass"], e.get("notes", ""), "",
            to_unix(e.get("created")),
            to_unix(e.get("modified") or e.get("changed") or e.get("created")), "Personal"]


def parse_proton_json(text):
    data = json.loads(text)
    vaults = data.get("vaults") if isinstance(data, dict) else None
    if not isinstance(vaults, dict):
        raise ValueError("el JSON no tiene el formato de Proton Pass")
    if data.get("encrypted"):
        raise ValueError("la exportación está cifrada; expórtala sin cifrar o en CSV")
    entries, skipped = [], 0
    for vault in vaults.values():
        for item in (vault.get("items") or []):
            d = item.get("data") or {}
            c, meta = d.get("content") or {}, d.get("metadata") or {}
            if item.get("state") == 2 or d.get("type") != "login":  # papelera, alias, tarjetas, notas...
                skipped += 1
                continue
            urls = c.get("urls") or []
            entries.append({"sec": "webs", "user": (urls[0] if urls else "") or meta.get("name", ""),
                            "pass": c.get("password", ""),
                            "alias": proton_alias(c.get("itemUsername", ""), c.get("itemEmail", "")),
                            "notes": meta.get("note", ""), "created": from_unix(item.get("createTime")),
                            "changed": from_unix(item.get("modifyTime")),
                            "modified": modified_date(item.get("createTime"), item.get("modifyTime"))})
    return entries, skipped, "Proton Pass (JSON)"


def read_proton_zip(path):
    with zipfile.ZipFile(path) as z:
        names = z.namelist()
        target = next((n for n in names if n.endswith("data.json")), None)
        if not target:
            if any(n.endswith("data.pgp") for n in names):
                raise ValueError("la exportación está cifrada (PGP); expórtala sin cifrar o en CSV")
            raise ValueError("el ZIP no contiene data.json")
        if z.getinfo(target).file_size > 100 * 1024 * 1024:
            raise ValueError("el archivo es demasiado grande")
        return z.read(target).decode("utf-8")


def parse_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = [{(k or "").strip().lower(): (v or "").strip() for k, v in r.items()} for r in reader]
        cols = {(c or "").strip().lower() for c in (reader.fieldnames or [])}
    if "password" not in cols:
        raise ValueError("formato no reconocido (se esperan las columnas de Proton Pass, Chrome/Edge o de esta app)")
    entries, skipped = [], 0
    if "section" in cols:
        fmt = "CSV de esta app"
        for r in rows:
            sec = r.get("section", "").lower()
            if sec not in SECTIONS:
                skipped += 1
                continue
            entries.append({"sec": sec, "user": r.get("user", ""), "pass": r["password"], "alias": r.get("alias", ""),
                            "notes": r.get("notes", ""), "created": r.get("created", ""),
                            "changed": r.get("changed", ""), "modified": r.get("modified", "")})
    elif cols & {"email", "vault", "type"}:
        fmt = "Proton Pass (CSV)"
        for r in rows:
            if r.get("type", "login") != "login":  # alias, tarjetas, identidades, notas, personalizados
                skipped += 1
                continue
            entries.append({"sec": "webs", "user": r.get("url") or r.get("name", ""), "pass": r["password"],
                            "alias": proton_alias(r.get("username", ""), r.get("email", "")),
                            "notes": r.get("note", ""), "created": from_unix(r.get("createtime")),
                            "changed": from_unix(r.get("modifytime")),
                            "modified": modified_date(r.get("createtime"), r.get("modifytime"))})
    elif "url" in cols:
        fmt = "CSV de Chrome/Edge"
        for r in rows:
            entries.append({"sec": "webs", "user": r.get("url") or r.get("name", ""), "pass": r["password"],
                            "alias": r.get("username", ""), "notes": r.get("note", ""), "created": "", "changed": ""})
    else:
        raise ValueError("formato no reconocido (se esperan las columnas de Proton Pass, Chrome/Edge o de esta app)")
    return entries, skipped, fmt


def parse_import(path):
    """Devuelve (entradas, omitidas, nombre del formato)."""
    ext = os.path.splitext(path)[1].lower()
    if ext == ".pgp":
        raise ValueError("la exportación está cifrada (PGP); expórtala sin cifrar o en CSV")
    if ext == ".zip":
        return parse_proton_json(read_proton_zip(path))[:2] + ("Proton Pass (ZIP)",)
    if ext == ".json":
        with open(path, encoding="utf-8-sig") as f:
            return parse_proton_json(f.read())
    return parse_csv(path)


# ---------- Comprobación de brechas ----------
# Contraseñas: Have I Been Pwned "Pwned Passwords" (k-anonimato: solo se envían 5 caracteres del SHA-1).
# Correos: XposedOrNot (gratuito; límite por IP: 2/s, 25/hora, 100/día).
HTTP_HEADERS = {"User-Agent": "GestorContrasenas/1.0"}
EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9\-]+(?:\.[A-Za-z0-9\-]+)+")
MAIL_PER_RUN = 25
MAIL_TTL_DAYS = 30
AUTO_DAYS = 7


class RateLimited(Exception):
    pass


def http_get(url, headers=None, timeout=15):
    req = urllib.request.Request(url, headers={**HTTP_HEADERS, **(headers or {})})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", "replace")


def hibp_range(prefix):
    """Devuelve {sufijo_sha1: nº de veces vista} para todos los hashes que empiezan por `prefix`."""
    body = http_get("https://api.pwnedpasswords.com/range/" + prefix, {"Add-Padding": "true"})
    out = {}
    for line in body.splitlines():
        suffix, _, n = line.partition(":")
        if n.strip().isdigit() and int(n) > 0:  # las filas de relleno tienen contador 0
            out[suffix.strip().upper()] = int(n)
    return out


def xon_check(email):
    """Lista de brechas (nombres) en las que aparece el correo; [] si no aparece."""
    try:
        body = http_get("https://api.xposedornot.com/v1/check-email/" + quote(email, safe="@"))
    except urllib.error.HTTPError as e:
        if e.code == 429:
            raise RateLimited()
        if e.code == 404:
            return []
        raise
    data = json.loads(body)
    breaches = data.get("breaches") if isinstance(data, dict) else None
    if isinstance(breaches, list) and breaches and isinstance(breaches[0], list):
        breaches = breaches[0]
    return [str(b) for b in breaches] if isinstance(breaches, list) else []


def scan(passwords, emails, progress, cancel, fetch_range=hibp_range, fetch_email=xon_check, pause=0.6):
    """Se ejecuta en un hilo (no toca Tk). Devuelve un dict con los resultados en bruto."""
    res = {"pw": {}, "mail": {}, "pw_total": 0, "pw_errors": 0, "mail_errors": 0,
           "rate_limited": False, "cancelled": False}
    by_prefix = {}
    for p in passwords:
        h = hashlib.sha1(p.encode("utf-8")).hexdigest().upper()
        by_prefix.setdefault(h[:5], []).append((h[5:], p))
    res["pw_total"] = len(by_prefix)

    def work(prefix):
        try:
            return prefix, fetch_range(prefix)
        except Exception:
            return prefix, None

    done = 0
    with ThreadPoolExecutor(6) as ex:
        futs = [ex.submit(work, pr) for pr in by_prefix]
        for f in as_completed(futs):
            if cancel.is_set():
                for x in futs:
                    x.cancel()
                res["cancelled"] = True
                break
            prefix, found = f.result()
            done += 1
            progress("pw", done, len(futs))
            if found is None:
                res["pw_errors"] += len(by_prefix[prefix])
                continue
            for suffix, p in by_prefix[prefix]:
                if suffix in found:
                    res["pw"][p] = found[suffix]
    if res["cancelled"]:
        return res

    failures = 0
    for n, em in enumerate(emails):
        if cancel.is_set():
            res["cancelled"] = True
            break
        try:
            res["mail"][em] = fetch_email(em)
            failures = 0
        except RateLimited:
            res["rate_limited"] = True
            break
        except Exception:
            res["mail_errors"] += 1
            failures += 1
            if failures >= 3:  # sin conexión o servicio caído: no insistir
                break
        progress("mail", n + 1, len(emails))
        cancel.wait(pause)
    return res


# ---------- Conexión con la extensión del navegador ----------
# Servidor HTTP solo en 127.0.0.1. Cada petición debe llevar: Host local, Origin de extensión
# (chrome-extension://…, algo que una web normal no puede falsificar) y la clave secreta generada aquí.
BRIDGE_PORT = 47822
BRIDGE_TTL = 600  # segundos que se conserva un aviso si el Gestor está bloqueado


def host_of(url):
    u = (url or "").strip()
    if "://" not in u:
        u = "https://" + u
    try:
        h = (urlparse(u).hostname or "").lower()
    except ValueError:
        return ""
    return h[4:] if h.startswith("www.") else h


def origin_of(url):
    p = urlparse(url)
    return f"{p.scheme}://{p.netloc.split('@')[-1].lower()}"


def find_web(webs, host, username):
    """Índice de la entrada de `host` cuyo usuario/correo coincide (el alias puede ser «user (mail)»)."""
    wanted = username.strip().lower()
    for i, e in enumerate(webs):
        if host_of(e["user"]) != host:
            continue
        tokens = {t for t in re.split(r"[\s()<>,;]+", e.get("alias", "").lower()) if t}
        if wanted in tokens:
            return i
    return None


def clean_credential(d):
    """Valida el JSON recibido; devuelve (url, usuario, contraseña) o None."""
    if not isinstance(d, dict):
        return None
    url, user, pw = d.get("url"), d.get("username"), d.get("password")
    if not all(isinstance(x, str) for x in (url, user, pw)):
        return None
    if not (0 < len(url) <= 2048 and 0 < len(user) <= 256 and 0 < len(pw) <= 1024):
        return None
    if urlparse(url).scheme not in ("http", "https") or not host_of(url):
        return None
    return url, user.strip(), pw


class Bridge:
    def __init__(self, port, token, on_item, is_unlocked):
        self.port, self.token, self.on_item, self.is_unlocked = port, token, on_item, is_unlocked
        self.httpd = None

    @property
    def running(self):
        return self.httpd is not None

    def start(self):
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def log_message(self, *args):
                pass

            def _reply(self, code, obj=None):
                body = json.dumps(obj or {}).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                origin = self.headers.get("Origin", "")
                if origin.startswith("chrome-extension://"):
                    self.send_header("Access-Control-Allow-Origin", origin)
                self.end_headers()
                self.wfile.write(body)

            def _allowed(self):
                if self.headers.get("Host", "") not in (f"127.0.0.1:{bridge.port}", f"localhost:{bridge.port}"):
                    return False  # protege contra DNS rebinding
                if not self.headers.get("Origin", "").startswith("chrome-extension://"):
                    return False
                return hmac.compare_digest(self.headers.get("X-GP-Token", "").encode("utf-8", "replace"),
                                           bridge.token.encode())

            def do_OPTIONS(self):
                if not self._allowed_origin_only():
                    return self._reply(403)
                self.send_response(204)
                self.send_header("Access-Control-Allow-Origin", self.headers["Origin"])
                self.send_header("Access-Control-Allow-Headers", "Content-Type, X-GP-Token")
                self.send_header("Access-Control-Allow-Methods", "POST, GET")
                self.send_header("Content-Length", "0")
                self.end_headers()

            def _allowed_origin_only(self):
                return (self.headers.get("Host", "") in (f"127.0.0.1:{bridge.port}", f"localhost:{bridge.port}")
                        and self.headers.get("Origin", "").startswith("chrome-extension://"))

            def do_GET(self):
                if self.path != "/ping" or not self._allowed():
                    return self._reply(403)
                self._reply(200, {"ok": True, "locked": not bridge.is_unlocked()})

            def do_POST(self):
                if self.path != "/credential" or not self._allowed():
                    return self._reply(403)
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    return self._reply(400)
                if not 0 < length <= 8192:
                    return self._reply(413)
                try:
                    item = clean_credential(json.loads(self.rfile.read(length)))
                except ValueError:
                    item = None
                if not item:
                    return self._reply(400)
                bridge.on_item({"url": item[0], "username": item[1], "password": item[2], "t": time.time()})
                self._reply(200, {"status": "received", "locked": not bridge.is_unlocked()})

        self.httpd = ThreadingHTTPServer(("127.0.0.1", self.port), Handler)
        self.httpd.daemon_threads = True
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None


# ---------- Comprobación de webs (¿siguen en funcionamiento?) ----------
WEB_UA = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) GestorContrasenas/2.0 (+comprobacion-de-webs)"}
WEB_TIMEOUT = 7


def _web_status(url, method, verify, timeout):
    ctx = ssl.create_default_context() if verify else ssl._create_unverified_context()
    req = urllib.request.Request(url, headers=WEB_UA, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as r:
            return r.status  # solo cabeceras: no se descarga la página
    except urllib.error.HTTPError as e:
        return e.code


def _why(e):
    inner = getattr(e, "reason", e)
    if isinstance(inner, socket.gaierror):
        return "No se encuentra el dominio (DNS)"
    if isinstance(inner, (socket.timeout, TimeoutError)) or "timed out" in str(inner):
        return "Tiempo de espera agotado"
    if isinstance(inner, ConnectionRefusedError):
        return "Conexión rechazada"
    if isinstance(inner, ssl.SSLError):
        return "Error de certificado/TLS"
    return str(inner)[:80] or "Sin respuesta"


def check_site(raw, timeout=WEB_TIMEOUT):
    """Devuelve (estado, motivo): True = responde, False = no disponible, None = no es una dirección web.
    Un sitio «responde» si contesta, aunque bloquee a los robots (401, 403, 429...). No disponible: no se
    puede conectar (DNS, rechazo, tiempo agotado), o contesta 404/410 o un error del servidor (5xx)."""
    u = raw.strip()
    if "://" not in u:
        u = "https://" + u
    host = urlparse(u).hostname or ""
    if not host or ("." not in host and ":" not in host) or " " in raw.strip():
        return None, "no es una dirección web"
    urls = [u] + (["http://" + u[len("https://"):]] if u.startswith("https://") else [])
    reason = "Sin respuesta"
    for url in urls:
        for method in ("HEAD", "GET"):
            try:
                try:
                    status = _web_status(url, method, True, timeout)
                except ssl.SSLError:
                    status = _web_status(url, method, False, timeout)  # certificado raro: el sitio sigue ahí
                except urllib.error.URLError as e:
                    if isinstance(getattr(e, "reason", None), ssl.SSLError):
                        status = _web_status(url, method, False, timeout)
                    else:
                        raise
            except (urllib.error.URLError, OSError, ValueError) as e:
                reason = _why(e)
                break  # sin conexión: probar la otra dirección, no repetir con GET
            if method == "HEAD" and status in (400, 403, 405, 501):
                continue  # algunos servidores no admiten HEAD: se repite con GET
            if status in (404, 410):
                return False, f"HTTP {status}: la página no existe"
            if status >= 500:
                return False, f"HTTP {status}: error del servidor"
            return True, f"HTTP {status}"
    return False, reason


# ---------- Antifuerza bruta y registro de accesos denegados ----------
LOCK_ATTEMPTS = 2  # intentos disponibles antes de bloquear
DENIED_MAX = 500   # entradas que se conservan en el registro


def lock_seconds(count):
    """Duración del bloqueo según cuántos se han producido: 1.º 10 min, 2.º 1 día, y un día más cada vez."""
    return 600 if count <= 1 else (count - 1) * 86400


def guard_now(cfg, now=None):
    """Hora de referencia que nunca retrocede: atrasar el reloj de Windows no acorta un bloqueo."""
    now = time.time() if now is None else now
    eff = max(now, cfg.get("lock_seen", 0))
    cfg["lock_seen"] = eff
    return eff


def lock_remaining(cfg, now=None):
    return max(0, math.ceil(cfg.get("lock_until", 0) - guard_now(cfg, now)))


def attempts_left(cfg):
    return max(0, LOCK_ATTEMPTS - cfg.get("lock_fails", 0))


def register_failure(cfg, now=None):
    """Anota un intento fallido. Devuelve los segundos de bloqueo aplicados (0 si aún quedan intentos)."""
    eff = guard_now(cfg, now)
    cfg["lock_fails"] = cfg.get("lock_fails", 0) + 1
    if cfg["lock_fails"] >= LOCK_ATTEMPTS:
        cfg["lock_count"] = cfg.get("lock_count", 0) + 1
        secs = lock_seconds(cfg["lock_count"])
        cfg["lock_until"] = eff + secs
        cfg["lock_fails"] = 0  # al acabar el bloqueo se vuelve a tener el máximo de intentos
        return secs
    return 0


def register_success(cfg):
    cfg["lock_fails"], cfg["lock_count"], cfg["lock_until"] = 0, 0, 0


def fmt_remaining(sec):
    d, rest = divmod(int(sec), 86400)
    h, rest = divmod(rest, 3600)
    m, s = divmod(rest, 60)
    if d:
        return f"{d} día{'s' if d != 1 else ''} {h} h {m:02d} min {s:02d} s"
    if h:
        return f"{h} h {m:02d} min {s:02d} s"
    return f"{m} min {s:02d} s"


def caps_on():
    """¿Está activado el bloqueo de mayúsculas? (Windows)"""
    try:
        import ctypes
        return bool(ctypes.windll.user32.GetKeyState(0x14) & 1)
    except Exception:
        return False


def _b64(b):
    return base64.b64encode(b).decode()


def deny_keypair():
    """Par de claves X25519: la pública se guarda en la configuración (para cifrar sin la contraseña maestra)
    y la privada dentro del almacén cifrado (para leer el registro con la app desbloqueada)."""
    priv = X25519PrivateKey.generate()
    return (_b64(priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw,
                                    serialization.NoEncryption())), pub_from_priv_obj(priv))


def pub_from_priv_obj(priv):
    return _b64(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw))


def pub_from_priv(priv_b64):
    return pub_from_priv_obj(X25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64)))


def _seal_key(shared):
    return HKDF(hashes.SHA256(), 32, None, b"gestor-denied-v1").derive(shared)


def seal(pub_b64, obj):
    """Cifrado de «caja sellada»: cualquiera con la clave pública puede escribir; solo la privada puede leer."""
    eph = X25519PrivateKey.generate()
    shared = eph.exchange(X25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)))
    nonce = os.urandom(12)
    ct = AESGCM(_seal_key(shared)).encrypt(nonce, json.dumps(obj).encode("utf-8"), None)
    eph_pub = eph.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return _b64(eph_pub + nonce + ct)


def unseal(priv_b64, blob_b64):
    raw = base64.b64decode(blob_b64)
    priv = X25519PrivateKey.from_private_bytes(base64.b64decode(priv_b64))
    shared = priv.exchange(X25519PublicKey.from_public_bytes(raw[:32]))
    return json.loads(AESGCM(_seal_key(shared)).decrypt(raw[32:44], raw[44:], None).decode("utf-8"))


def device_label():
    try:
        name = f"{platform.system()} {platform.release()}"
        if platform.system() == "Windows" and int(platform.version().split(".")[-1]) >= 22000:
            name = "Windows 11"
        return f"PC · {name} · {socket.gethostname()}"
    except Exception:
        return "PC"


def geo_lookup(timeout=6):
    """IP pública y ubicación aproximada (servicio ipwho.is). Sin conexión devuelve campos vacíos."""
    try:
        req = urllib.request.Request("https://ipwho.is/", headers=HTTP_HEADERS)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            d = json.load(r)
        if d.get("success"):
            return {"ip": d.get("ip", ""), "loc": ", ".join(x for x in (d.get("city"), d.get("region"),
                                                                       d.get("country")) if x)}
    except Exception:
        pass
    return {"ip": "", "loc": ""}


def dpapi_protect(data):
    """Cifra con DPAPI de Windows (atado a tu usuario de Windows en este PC, sin contraseña maestra)."""
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    inb, out = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), Blob()
    if not ctypes.windll.crypt32.CryptProtectData(ctypes.byref(inb), "gestor", None, None, None, 0, ctypes.byref(out)):
        raise OSError("DPAPI no disponible")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


def dpapi_unprotect(data):
    import ctypes
    from ctypes import wintypes

    class Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    buf = ctypes.create_string_buffer(data, len(data))
    inb, out = Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), Blob()
    if not ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(inb), None, None, None, None, 0, ctypes.byref(out)):
        raise OSError("DPAPI no pudo descifrar")
    try:
        return ctypes.string_at(out.pbData, out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(out.pbData)


_denied_lock = threading.Lock()


def denied_path():
    return os.path.join(APP_DIR, "denied.json")


def denied_load():
    try:
        with open(denied_path(), encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, list) else []
    except (OSError, ValueError):
        return []


def _denied_save(items):
    os.makedirs(APP_DIR, exist_ok=True)
    tmp = denied_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(items[-DENIED_MAX:], f)
    os.replace(tmp, denied_path())


def denied_clear():
    with _denied_lock:
        _denied_save([])


def record_denied(pub_b64, password, geo=geo_lookup, wait=False):
    """Registra un intento fallido: contraseña, IP, ubicación, fecha y dispositivo, todo cifrado con la clave
    pública. La ubicación se busca en segundo plano y se completa después."""
    eid = uuid.uuid4().hex
    try:
        lan = (lan_ips() or [""])[0]
    except OSError:
        lan = ""
    payload = {"pw": password, "ip": "", "lan": lan, "loc": "", "dev": device_label()}

    def store(p):
        entry = {"id": eid, "t": now_iso(), "rev": now_rev()}  # rev: para fusionar con el otro dispositivo
        if pub_b64:
            entry["blob"] = seal(pub_b64, p)
        else:
            # Aún no existe la clave del registro (nada se ha desbloqueado desde que se estrenó esta función):
            # se protege con DPAPI y se pasa a la caja sellada en el primer desbloqueo (ver denied_migrate).
            try:
                entry["dp"] = _b64(dpapi_protect(json.dumps(p).encode("utf-8")))
            except Exception:
                entry["plain"] = {**p, "pw": None}  # sin DPAPI no se guarda la contraseña
        return entry

    with _denied_lock:
        items = denied_load()
        items.append(store(payload))
        _denied_save(items)

    def finish():
        g = geo()
        full = {**payload, "ip": g.get("ip", ""), "loc": g.get("loc", "")}
        with _denied_lock:
            items = denied_load()
            for e in items:
                if e.get("id") == eid:
                    t0 = e.get("t")
                    for k in ("blob", "plain", "dp"):
                        e.pop(k, None)
                    e.update(store(full))
                    e["id"], e["t"] = eid, t0  # se conserva el momento original del intento
            _denied_save(items)

    if wait:
        finish()
    else:
        threading.Thread(target=finish, daemon=True).start()
    return eid


def denied_migrate(pub_b64):
    """Pasa a la caja sellada los intentos que se protegieron con DPAPI antes de que existiera la clave."""
    with _denied_lock:
        items, changed = denied_load(), False
        for e in items:
            if e.get("dp"):
                try:
                    payload = json.loads(dpapi_unprotect(base64.b64decode(e["dp"])).decode("utf-8"))
                    e["blob"] = seal(pub_b64, payload)
                    e["rev"] = now_rev()
                    del e["dp"]
                    changed = True
                except Exception:
                    pass  # otro usuario de Windows u otro PC: se deja como está
        if changed:
            _denied_save(items)


def can_unseal(priv_b64, blob_b64):
    try:
        unseal(priv_b64, blob_b64)
        return True
    except Exception:
        return False


def denied_synced():
    """Intentos ya cifrados (los únicos que se comparten con el otro dispositivo), sin datos locales."""
    return [{k: e[k] for k in ("id", "t", "blob", "rev") if k in e} for e in denied_load() if e.get("blob")]


def denied_merge(remote, deleted=None):
    """Incorpora intentos del otro dispositivo (gana la revisión más reciente de cada id) y aplica los borrados.
    Devuelve cuántos son nuevos."""
    deleted = deleted or {}
    with _denied_lock:
        items = denied_load()
        mine = {e["id"]: e for e in items if e.get("blob") and e.get("id")}
        new = 0
        for r in remote or []:
            if not (isinstance(r, dict) and isinstance(r.get("id"), str) and isinstance(r.get("blob"), str)
                    and 0 < len(r["id"]) <= 64 and len(r["blob"]) <= 4096):
                continue
            rev = str(r.get("rev", ""))[:40]
            if r["id"] in deleted and deleted[r["id"]] >= rev:
                continue
            cur = mine.get(r["id"])
            if cur is None:
                new += 1
                mine[r["id"]] = {"id": r["id"], "t": str(r.get("t", ""))[:40], "blob": r["blob"], "rev": rev}
            elif rev > cur.get("rev", ""):
                mine[r["id"]] = {"id": r["id"], "t": cur.get("t", ""), "blob": r["blob"], "rev": rev}
        mine = {i: e for i, e in mine.items() if i not in deleted or e.get("rev", "") > deleted[i]}
        others = [e for e in items if not e.get("blob")]
        _denied_save(others + sorted(mine.values(), key=lambda e: e.get("t", "")))
        return new


def read_denied(priv_b64):
    """Registro descifrado, del más reciente al más antiguo."""
    out = []
    for e in denied_load():
        if e.get("dp"):  # pendiente de migrar (no debería verse: se migra al desbloquear)
            try:
                out.append({"t": e.get("t", ""), **json.loads(dpapi_unprotect(base64.b64decode(e["dp"])).decode("utf-8"))})
            except Exception:
                out.append({"t": e.get("t", ""), "pw": None, "ip": "", "lan": "", "loc": "", "dev": "(no se puede descifrar)"})
            continue
        if e.get("blob"):
            try:
                p = unseal(priv_b64, e["blob"]) if priv_b64 else None
            except Exception:
                p = None
            # Lo más habitual: lo cifró el móvil con su propia clave y aún no se ha sincronizado con este PC
            p = p or {"pw": None, "ip": "", "lan": "", "loc": "",
                      "dev": "(cifrado con otra clave: se verá al sincronizar con el móvil)"}
        else:
            p = e.get("plain") or {}
        out.append({"t": e.get("t", ""), **p})
    out.reverse()
    out.sort(key=lambda r: r.get("t", ""), reverse=True)  # más reciente primero (estable: empates, el último añadido antes)
    return out


def denied_unseen(cfg):
    seen = cfg.get("denied_seen", "")
    return sum(1 for e in denied_load() if e.get("t", "") > seen)


# ---------- Sincronización con el móvil (red local, TLS con certificado fijado) ----------
SYNC_PORT = 47823
PAIR_TTL = 300  # segundos de validez del código de vinculación
MAX_SYNC_BODY = 25 * 1024 * 1024


def ensure_cert():
    """Certificado autofirmado propio (se crea una vez). El móvil lo reconoce por su huella SHA-256,
    que viaja en el QR de vinculación: así no hace falta ninguna autoridad de certificación."""
    d = os.path.join(APP_DIR, "sync")
    os.makedirs(d, exist_ok=True)
    cert_path, key_path = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        key = ec.generate_private_key(ec.SECP256R1())
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Gestor de contrasenas")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
                .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
                .not_valid_after(now + timedelta(days=3650))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("gestor.local")]), critical=False)
                .sign(key, hashes.SHA256()))
        with open(key_path, "wb") as f:
            f.write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                      serialization.NoEncryption()))
        with open(cert_path, "wb") as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
    with open(cert_path, "rb") as f:
        der = x509.load_pem_x509_certificate(f.read()).public_bytes(serialization.Encoding.DER)
    return cert_path, key_path, hashlib.sha256(der).hexdigest()


def lan_ips():
    """Direcciones IPv4 privadas de este PC (la de la ruta principal, primero)."""
    found = []
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("10.255.255.255", 1))
        found.append(s.getsockname()[0])
        s.close()
    except OSError:
        pass
    try:
        found += [i[4][0] for i in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET)]
    except OSError:
        pass
    out = []
    for ip in found:
        a = ipaddress.ip_address(ip)
        if a.is_private and not a.is_loopback and not a.is_link_local and ip not in out:
            out.append(ip)
    return out


class SyncServer:
    """HTTPS en la red local. Los callbacks que tocan los datos se ejecutan en el hilo de la interfaz
    (`run_main`), nunca en los hilos del servidor."""

    def __init__(self, port, cert, key, run_main, pair, auth, sync, is_unlocked, denied=None):
        self.port, self.cert, self.key = port, cert, key
        self.run_main, self.pair, self.auth, self.sync, self.is_unlocked = run_main, pair, auth, sync, is_unlocked
        self.denied = denied or (lambda device, entries: (404, {}))
        self.httpd = None

    @property
    def running(self):
        return self.httpd is not None

    def start(self):
        srv = self
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(self.cert, self.key)

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"

            def setup(self):
                self.request.settimeout(20)
                self.request = ctx.wrap_socket(self.request, server_side=True)  # el handshake va en este hilo
                super().setup()

            def log_message(self, *args):
                pass

            def _json(self, code, obj):
                body = json.dumps(obj).encode()
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(body)

            def _body(self):
                try:
                    n = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    return None
                if not 0 < n <= MAX_SYNC_BODY:
                    return None
                try:
                    d = json.loads(self.rfile.read(n))
                except ValueError:
                    return None
                return d if isinstance(d, dict) else None

            def do_GET(self):
                if self.path == "/ping":
                    return self._json(200, {"app": "gestor", "locked": not srv.is_unlocked()})
                self._json(404, {})

            def do_POST(self):
                body = self._body()
                if body is None:
                    return self._json(400, {"error": "bad request"})
                if self.path == "/pair":
                    res = srv.pair(str(body.get("code", "")), str(body.get("name", ""))[:60])
                    return self._json(200, res) if res else self._json(403, {"error": "code"})
                if self.path == "/sync":
                    token = self.headers.get("Authorization", "")[7:]
                    device = srv.auth(token) if token else None
                    if not device:
                        return self._json(401, {"error": "auth"})
                    if not srv.is_unlocked():
                        return self._json(423, {"error": "locked"})
                    raw = body.get("blob")
                    try:
                        blob = base64.b64decode(raw, validate=True) if raw else None
                    except (ValueError, TypeError):
                        return self._json(400, {"error": "blob"})
                    status, out = srv.run_main(lambda: srv.sync(device, blob))
                    if status == 200:
                        return self._json(200, {"blob": base64.b64encode(out).decode()})
                    return self._json(status, {"error": {423: "locked", 409: "key"}.get(status, "error")})
                if self.path == "/denied":
                    # intentos fallidos del móvil: ya van cifrados con la clave pública, así que se aceptan aunque el
                    # PC esté bloqueado (no hace falta la contraseña maestra para guardarlos)
                    token = self.headers.get("Authorization", "")[7:]
                    device = srv.auth(token) if token else None
                    if not device:
                        return self._json(401, {"error": "auth"})
                    entries = body.get("entries")
                    if not isinstance(entries, list) or len(entries) > 100:
                        return self._json(400, {"error": "entries"})
                    status, out = srv.run_main(lambda: srv.denied(device, entries))
                    return self._json(status, out or {})
                self._json(404, {})

        class Server(ThreadingHTTPServer):
            daemon_threads = True

            def handle_error(self, request, client_address):
                pass  # clientes que no hablan TLS, conexiones cortadas...

        self.httpd = Server(("0.0.0.0", self.port), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self):
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
            self.httpd = None


# ---------- Widgets ----------
# ---------- Actualizaciones (VPS propio; manifiesto firmado con Ed25519) ----------
UPDATE_URL = "https://github.com/BadyX/gestor-contrasenas/releases/latest/download/"
UPDATE_PUBKEY = "I5Vnk0i8OHjCBhCZbL0Mum9j+pIvxksqj9W01crk60k="  # la clave privada solo está en el PC del autor
UPDATE_MAX = 80 * 1024 * 1024
UPDATE_FILE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")

UPDATE_PS1 = """param($esperar, $nuevo, $exe, $anterior)
try { Wait-Process -Id $esperar -Timeout 60 } catch {}
$ok = $false
for ($i = 0; $i -lt 40 -and -not $ok; $i++) {
  try {
    if (Test-Path -LiteralPath $anterior) { Remove-Item -LiteralPath $anterior -Force }
    Move-Item -LiteralPath $exe -Destination $anterior -Force -ErrorAction Stop
    $ok = $true
  } catch { Start-Sleep -Milliseconds 500 }
}
if (-not $ok) { exit 1 }
try { Move-Item -LiteralPath $nuevo -Destination $exe -Force -ErrorAction Stop }
catch { Move-Item -LiteralPath $anterior -Destination $exe -Force; exit 1 }
Start-Process -FilePath $exe
"""


def version_tuple(v):
    try:
        return tuple(int(x) for x in str(v).split("."))
    except ValueError:
        return (0,)


def fetch_bytes(url, timeout=15, limit=1024 * 1024):
    req = urllib.request.Request(url, headers=HTTP_HEADERS)
    with urllib.request.urlopen(req, timeout=timeout) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise ValueError("respuesta demasiado grande")
    return data


def verify_manifest(raw, sig_b64, pub_b64=UPDATE_PUBKEY):
    """Comprueba la firma del manifiesto y lo devuelve como dict (InvalidSignature si no es auténtico)."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    Ed25519PublicKey.from_public_bytes(base64.b64decode(pub_b64)).verify(base64.b64decode(sig_b64), raw)
    m = json.loads(raw.decode("utf-8"))
    if not (isinstance(m, dict) and isinstance(m.get("version"), str) and UPDATE_FILE.match(str(m.get("file", "")))
            and re.fullmatch(r"[0-9a-f]{64}", str(m.get("sha256", ""))) and isinstance(m.get("size"), int)
            and 0 < m["size"] <= UPDATE_MAX):
        raise ValueError("manifiesto no válido")
    return m


def check_update(base=UPDATE_URL, pub_b64=UPDATE_PUBKEY, current=None, fetch=fetch_bytes):
    """Devuelve el manifiesto de la versión nueva o None si ya está al día."""
    stamp = f"?t={int(time.time())}"
    raw = fetch(base + "version.json" + stamp)
    sig = fetch(base + "version.sig" + stamp).decode("ascii", "replace").strip()
    m = verify_manifest(raw, sig, pub_b64)
    return m if version_tuple(m["version"]) > version_tuple(current or APP_VERSION) else None


def download_update(m, dest, base=UPDATE_URL, progress=None, cancel=None):
    """Descarga el ejecutable a `dest` y comprueba tamaño y SHA-256 del manifiesto; si algo no cuadra, lo borra."""
    h, n = hashlib.sha256(), 0
    req = urllib.request.Request(base + m["file"], headers=HTTP_HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=20) as r, open(dest, "wb") as f:
            first = True
            while True:
                chunk = r.read(65536)
                if not chunk:
                    break
                if first and chunk[:2] != b"MZ":
                    raise ValueError("el archivo descargado no es un ejecutable")
                first = False
                n += len(chunk)
                if n > m["size"]:
                    raise ValueError("el archivo es más grande de lo anunciado")
                h.update(chunk)
                f.write(chunk)
                if progress:
                    progress(n, m["size"])
                if cancel and cancel():
                    raise InterruptedError("cancelado")
        if n != m["size"] or h.hexdigest() != m["sha256"]:
            raise ValueError("la descarga está corrupta (la huella SHA-256 no coincide)")
    except BaseException:
        try:
            os.remove(dest)
        except OSError:
            pass
        raise


def launch_swap(new_path, exe, anterior):
    """Lanza el ayudante que, al cerrarse este proceso, sustituye el exe (guardando el anterior) y lo reinicia."""
    import subprocess
    ps1 = os.path.join(APP_DIR, "actualizar.ps1")
    with open(ps1, "w", encoding="utf-8-sig") as f:
        f.write(UPDATE_PS1)
    env = {k: v for k, v in os.environ.items() if not k.startswith(("_PYI", "_MEIPASS"))}
    subprocess.Popen(["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-WindowStyle", "Hidden", "-File", ps1,
                      str(os.getpid()), new_path, exe, anterior], env=env, close_fds=True,
                     creationflags=0x08000000 | 0x00000008)  # sin ventana + desligado


def button(parent, text, command, primary=True, danger=False, **kw):
    bg = DANGER if danger else (ACCENT if primary else PANEL)
    hover = "#ff8294" if danger else (ACCENT_H if primary else HOVER)
    b = tk.Label(parent, text=text, bg=bg, fg="white" if (primary or danger) else TEXT, font=("Segoe UI", 11, "bold"),
                 padx=22, pady=9, cursor="hand2", highlightthickness=0 if (primary or danger) else 1,
                 highlightbackground=LINE, **kw)
    b.bind("<Button-1>", lambda e: command())
    b.bind("<Enter>", lambda e: b.config(bg=hover))
    b.bind("<Leave>", lambda e: b.config(bg=bg))
    return b


def entry(parent, show=None):
    return tk.Entry(parent, font=FONT, bg=BG, fg=TEXT, insertbackground=TEXT, relief="flat", show=show,
                    highlightthickness=1, highlightbackground=LINE, highlightcolor=ACCENT)


class Tooltip:
    """Etiqueta flotante justo debajo del puntero, con un pequeño retardo (`delay` ms)."""

    def __init__(self, widget, delay=350):
        self.widget, self.delay, self.job, self.tip = widget, delay, None, None
        widget.bind("<Destroy>", lambda e: self.hide(), add="+")

    def schedule(self, text, x, y):
        self.hide()
        self.job = self.widget.after(self.delay, self.show, text, x, y)

    def show(self, text, x, y):
        self.job = None
        tip = tk.Toplevel(self.widget)
        tip.wm_overrideredirect(True)
        tip.wm_attributes("-topmost", True)
        tk.Label(tip, text=text, bg=TEXT, fg=BG, font=("Segoe UI", 9), padx=8, pady=4,
                 wraplength=480, justify="left").pack()
        tip.update_idletasks()
        # debajo del puntero; si no cabe en pantalla, se desplaza hacia la izquierda
        x = min(x, tip.winfo_screenwidth() - tip.winfo_reqwidth() - 8)
        tip.wm_geometry(f"+{x}+{y + 22}")
        self.tip = tip

    def hide(self):
        if self.job:
            self.widget.after_cancel(self.job)
            self.job = None
        if self.tip:
            self.tip.destroy()
            self.tip = None


def add_tooltip(widget, text):
    t = Tooltip(widget)
    widget.bind("<Enter>", lambda e: t.schedule(text, e.x_root, e.y_root), add="+")
    widget.bind("<Leave>", lambda e: t.hide(), add="+")
    widget.bind("<Button-1>", lambda e: t.hide(), add="+")


def icon_btn(parent, text, command, hover=None, bg=None, tip=None):
    bg = bg or PANEL2
    b = tk.Label(parent, text=text, bg=bg, fg=MUTED, font=("Segoe UI Emoji", 11), cursor="hand2", padx=5)
    b.bind("<Button-1>", lambda e: command())
    b.bind("<Enter>", lambda e: b.config(fg=hover or TEXT))
    b.bind("<Leave>", lambda e: b.config(fg=MUTED))
    if tip:
        add_tooltip(b, tip)
    return b


def scroll_area(parent):
    """Área con scroll vertical. Devuelve (canvas, frame interior)."""
    wrap = tk.Frame(parent, bg=PANEL)
    wrap.pack(fill="both", expand=True, padx=(30, 12))
    canvas = tk.Canvas(wrap, bg=PANEL, highlightthickness=0)
    sb = tk.Scrollbar(wrap, orient="vertical", command=canvas.yview)
    inner = tk.Frame(canvas, bg=PANEL)
    win = canvas.create_window((0, 0), window=inner, anchor="nw")
    canvas.configure(yscrollcommand=sb.set)
    inner.bind("<Configure>", lambda e: canvas.configure(scrollregion=canvas.bbox("all")))
    canvas.bind("<Configure>", lambda e: canvas.itemconfig(win, width=e.width))
    canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-e.delta / 120), "units"))
    canvas.pack(side="left", fill="both", expand=True)
    sb.pack(side="right", fill="y")
    return canvas, inner


def strength_meter(parent):
    """Barra de 4 tramos. Devuelve (frame, función update(password))."""
    colors = strength_colors()
    f = tk.Frame(parent, bg=PANEL)
    cv = tk.Canvas(f, width=176, height=8, bg=PANEL, highlightthickness=0)
    cv.pack(side="left")
    lbl = tk.Label(f, text="", bg=PANEL, fg=MUTED, font=("Segoe UI", 9))
    lbl.pack(side="left", padx=8)

    def update(pw):
        level, text = strength(pw)
        cv.delete("all")
        for i in range(4):
            cv.create_rectangle(i * 44, 0, i * 44 + 40, 8, outline="", fill=colors[level] if i < level else LINE)
        lbl.config(text=text, fg=colors[level] if level else MUTED)

    update("")
    return f, update


# ---------- Aplicación ----------
class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.cfg = load_cfg()
        apply_theme(self.cfg["theme"])
        self.title("Gestor de contraseñas")
        try:
            self.iconbitmap(resource("icon.ico"))
        except tk.TclError:
            pass
        self.configure(bg=BG)
        w, h = 1040, 660
        self.geometry(f"{w}x{h}+{(self.winfo_screenwidth() - w) // 2}+{(self.winfo_screenheight() - h) // 2}")
        self.minsize(1040, 520)
        self.vault = Vault()
        self.current = "correos"
        self.query = ""
        self.sort = 0
        self.only_dups = False
        self.scan = None  # comprobación de brechas en curso
        self.webcheck, self.webcheck_ui = None, None  # comprobación de webs en curso
        self.unlocked = False
        self.in_form = False
        self.last_activity = time.time()
        for ev in ("<Key>", "<Motion>", "<Button>", "<MouseWheel>"):
            self.bind_all(ev, self.touch, add="+")
        self.after(5000, self.idle_check)
        # extensión del navegador: avisos pendientes (solo en memoria) y servidor local
        self.bridge, self.bridge_error, self.bridge_busy = None, "", False
        self.bridge_items = deque(maxlen=20)
        self.bridge_start()
        self.after(400, self.bridge_tick)
        # sincronización con el móvil
        self.sync_srv, self.sync_error, self.sync_fp, self.pair_state = None, "", "", None
        self.sync_jobs = queue.Queue()
        self.sync_start()
        self.after(150, self.sync_tick)
        # actualizaciones: se busca una vez al abrir (sin necesidad de desbloquear)
        self.update_q, self.update_busy = queue.Queue(), False
        self.after(2500, self.update_start)
        self.show_login()

    def touch(self, _=None):
        self.last_activity = time.time()

    def clear(self, widget):
        for c in widget.winfo_children():
            c.destroy()

    # --- Bloqueo automático ---
    def idle_check(self):
        minutes = self.cfg["lock_minutes"]
        if self.unlocked and minutes and time.time() - self.last_activity > minutes * 60:
            self.lock()
        self.after(5000, self.idle_check)

    def lock(self):
        for w in self.winfo_children():
            if isinstance(w, tk.Toplevel):
                w.destroy()
        self.unbind_all("<MouseWheel>")
        self.touch()
        if self.scan:
            self.scan["cancel"].set()
            self.scan = None
        if self.webcheck:
            self.webcheck["cancel"].set()
            self.webcheck = None
        self.in_form = False
        self.vault = Vault()  # los datos descifrados desaparecen de memoria
        self.current, self.query = "correos", ""
        self.show_login()

    # --- Pantalla de acceso ---
    def show_login(self):
        self.unlocked = False
        self.unbind("<Escape>")
        self.configure(bg=BG)
        self.clear(self)
        creating = not Vault.exists()
        box = tk.Frame(self, bg=PANEL, highlightthickness=1, highlightbackground=LINE, padx=40, pady=34)
        box.place(relx=0.5, rely=0.5, anchor="center")
        tk.Label(self, text=f"Versión {APP_VERSION}", bg=BG, fg=MUTED, font=("Segoe UI", 9)).place(relx=0.5, rely=1.0, y=-10, anchor="s")
        tk.Label(box, text="🔐", bg=PANEL, fg=TEXT, font=("Segoe UI Emoji", 34)).pack()
        title = tk.Label(box, text="Crea tu contraseña maestra" if creating else "Desbloquear",
                         bg=PANEL, fg=TEXT, font=("Segoe UI", 16, "bold"))
        title.pack(pady=(4, 2))
        subtitle = tk.Label(box, text=("Cifrará todos tus datos. Si la olvidas no se pueden recuperar."
                                       if creating else "Introduce tu contraseña maestra"),
                            bg=PANEL, fg=MUTED, font=("Segoe UI", 10), wraplength=300)
        subtitle.pack(pady=(0, 16))
        p1 = entry(box, show="•")
        p1.pack(fill="x", ipady=7)
        p2 = None
        if creating:
            tk.Label(box, text="Repítela", bg=PANEL, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(10, 2))
            p2 = entry(box, show="•")
            p2.pack(fill="x", ipady=7)
        caps = tk.Label(box, text="", bg=PANEL, fg=WARN, font=("Segoe UI Emoji", 10, "bold"))
        caps.pack(pady=(6, 0))
        attempts = tk.Label(box, text="", bg=PANEL, fg=MUTED, font=("Segoe UI", 10))
        if not creating:
            attempts.pack(pady=(2, 0))
        msg = tk.Label(box, text="", bg=PANEL, fg=DANGER, font=("Segoe UI", 10), wraplength=320, justify="center")
        msg.pack(pady=8)
        ui = {"btn": None, "locked": False, "ticks": 0}

        def refresh():
            """Bloq Mayús, intentos disponibles y bloqueo (con cuenta atrás). Se repite cada 300 ms."""
            try:
                if not box.winfo_exists():
                    return
                if ui.get("job"):
                    self.after_cancel(ui["job"])
            except (tk.TclError, ValueError):
                return
            caps.config(text="⚠ El bloqueo de mayúsculas está activado" if caps_on() else "")
            if not creating:
                left = lock_remaining(self.cfg)
                ui["ticks"] += 1
                if ui["ticks"] % 50 == 0:
                    save_cfg(self.cfg)  # conserva la «hora que no retrocede» aunque se cierre la app
                if left > 0:
                    if not ui["locked"]:
                        ui["locked"] = True
                        p1.delete(0, "end")
                        for w in (title, subtitle, p1, ui["btn"]):  # bloqueada: solo el icono, los intentos y la cuenta atrás
                            w.pack_forget()
                    attempts.config(text=f"Intentos disponibles: 0 de {LOCK_ATTEMPTS}", fg=DANGER)
                    msg.config(text=f"🔒 La aplicación está bloqueada.\nTiempo restante: {fmt_remaining(left)}",
                               fg=DANGER)
                else:
                    if ui["locked"]:
                        ui["locked"] = False
                        save_cfg(self.cfg)
                        # vuelve todo como siempre, en el mismo orden (cada uno justo antes de «caps»)
                        title.pack(pady=(4, 2), before=caps)
                        subtitle.pack(pady=(0, 16), before=caps)
                        p1.config(state="normal")
                        p1.pack(fill="x", ipady=7, before=caps)
                        ui["btn"].pack(fill="x")
                        msg.config(text="Ya puedes volver a intentarlo.", fg=OK)
                        p1.focus_set()
                    n = attempts_left(self.cfg)
                    attempts.config(text=f"Intentos disponibles: {n} de {LOCK_ATTEMPTS}", fg=DANGER if n == 1 else MUTED)
            ui["job"] = self.after(300, refresh)

        def go(_=None):
            pw = p1.get()
            if creating:
                if len(pw) < 6:
                    msg.config(text="Mínimo 6 caracteres.")
                elif pw != p2.get():
                    msg.config(text="Las contraseñas no coinciden.")
                else:
                    self.vault.create(pw)
                    self.show_main()
                return
            if ui["locked"] or lock_remaining(self.cfg) > 0:
                return  # bloqueada: no se admite ninguna contraseña
            self.config(cursor="watch")
            self.update_idletasks()
            try:
                ok = self.vault.unlock(pw)
            except Exception as ex:
                self.config(cursor="")
                msg.config(text=f"No se pudo leer el archivo: {ex}", fg=DANGER)
                return
            self.config(cursor="")
            if ok:
                register_success(self.cfg)
                save_cfg(self.cfg)
                self.show_main()
                self.after_login()
            else:
                secs = register_failure(self.cfg)
                save_cfg(self.cfg)
                record_denied(self.cfg.get("deny_pub", ""), pw)  # queda en «Accesos denegados» (cifrado)
                p1.delete(0, "end")
                if secs:
                    refresh()
                else:
                    msg.config(text="Contraseña incorrecta.", fg=DANGER)
                    n = attempts_left(self.cfg)
                    attempts.config(text=f"Intentos disponibles: {n} de {LOCK_ATTEMPTS}", fg=DANGER if n == 1 else MUTED)

        ui["btn"] = button(box, "Crear y entrar" if creating else "Entrar", go)
        ui["btn"].pack(fill="x")
        tk.Label(self, text="© BadyX  ·  24/10/2026", bg=BG, fg=MUTED, font=("Segoe UI", 9)).place(
            relx=1.0, rely=1.0, anchor="se", x=-20, y=-10)
        self.bind("<Return>", go)
        p1.focus_set()
        refresh()

    # --- Pantalla principal ---
    def toggle_theme(self):
        self.cfg["theme"] = "light" if self.cfg["theme"] == "dark" else "dark"
        save_cfg(self.cfg)
        apply_theme(self.cfg["theme"])
        self.show_main()  # se reconstruye con los colores nuevos, en la misma sección

    def show_main(self):
        self.unlocked = True
        if self.vault.dirty:  # primera vez con sincronización: se guardan los ids asignados a las entradas
            self.vault.save()
        self.ensure_deny_key()
        self.unbind("<Return>")
        self.unbind("<Escape>")
        self.unbind_all("<MouseWheel>")
        self.configure(bg=BG)
        self.clear(self)
        nav = tk.Frame(self, bg=PANEL2, width=256)
        nav.pack(side="left", fill="y")
        nav.pack_propagate(False)
        tk.Label(nav, text="🔐  Mis claves", bg=PANEL2, fg=TEXT, font=("Segoe UI Emoji", 14, "bold"),
                 anchor="w").pack(fill="x", padx=20, pady=(26, 22))

        def nav_label(text, command):
            b = tk.Label(nav, text=text, bg=PANEL2, fg=MUTED, font=("Segoe UI", 11), anchor="w", padx=14, pady=11,
                         cursor="hand2")
            b.bind("<Button-1>", lambda e: command())
            return b

        self.nav_btns = {}
        for key in SECTIONS:
            self.nav_btns[key] = nav_label("", lambda k=key: self.select(k))
            self.nav_btns[key].pack(fill="x", padx=12, pady=3)
        self.nav_btns["breach"] = nav_label("", lambda: self.select("breach"))
        self.nav_btns["breach"].pack(fill="x", padx=12, pady=3)
        self.nav_btns["gen"] = nav_label("", self.show_generator)  # acción (no es una sección): abre el generador
        self.nav_btns["gen"].pack(fill="x", padx=12, pady=3)
        self.nav_btns["denied"] = nav_label("", lambda: self.select("denied"))
        self.nav_btns["denied"].pack(fill="x", padx=12, pady=3)
        tk.Frame(nav, bg=LINE, height=1).pack(fill="x", padx=20, pady=10)
        self.nav_btns["admin"] = nav_label("", self.open_admin)
        self.nav_btns["admin"].pack(fill="x", padx=12, pady=3)
        self.nav_btns["changelog"] = nav_label("", lambda: self.select("changelog"))
        self.nav_btns["changelog"].pack(fill="x", padx=12, pady=3)
        # parte baja del menú
        nav_label("🔒  Bloquear ahora", self.lock).pack(side="bottom", fill="x", padx=12, pady=(0, 14))
        nav_label("☀  Modo claro" if self.cfg["theme"] == "dark" else "🌙  Modo oscuro",
                  self.toggle_theme).pack(side="bottom", fill="x", padx=12, pady=3)

        right = tk.Frame(self, bg=PANEL)
        right.pack(side="left", fill="both", expand=True)
        foot = tk.Label(right, text="© BadyX  ·  24/10/2026", bg=PANEL, fg=MUTED, font=("Segoe UI", 9), anchor="e",
                        padx=30, pady=6)
        foot.pack(side="bottom", fill="x")
        tk.Label(foot, text=f"Versión {APP_VERSION}", bg=PANEL, fg=MUTED, font=("Segoe UI", 9)).place(relx=0.5, rely=0.5, anchor="center")
        self.main = tk.Frame(right, bg=PANEL)
        self.main.pack(fill="both", expand=True)
        self.refresh()

    def refresh(self):
        {"admin": self.show_admin, "breach": self.show_breach, "denied": self.show_denied,
         "changelog": self.show_changelog}.get(self.current, self.show_list)()

    def refresh_nav(self):
        for key, b in self.nav_btns.items():
            active = key == self.current
            if key == "admin":
                text = "⚙  Administrador"
            elif key == "gen":
                text = "🎲  Generador de contraseñas"
            elif key == "denied":
                text = ("⚠" if denied_unseen(self.cfg) else "🚫") + "  Accesos denegados"  # ⚠ = hay intentos sin revisar
            elif key == "changelog":
                text = "📜  Changelog"
            elif key == "breach":
                n = len(self.vault.data["brechas"].get("findings", []))
                text = "🛡  Brechas" + (f"   ⚠ {n}" if n else "")
            else:
                text = f"{SECTIONS[key]['icon']}  {SECTIONS[key]['title']}   ({len(self.vault.data[key])})"
            b.config(text=text, bg=ACCENT if active else PANEL2, fg="white" if active else MUTED)

    def select(self, key):
        if key != self.current:
            self.query, self.only_dups = "", False  # los filtros se reinician al cambiar de sección
        self.current = key
        {"breach": self.show_breach, "denied": self.show_denied,
         "changelog": self.show_changelog}.get(key, self.show_list)()

    # --- Duplicados ---
    def merge_group(self, section, group, keep):
        """Deja solo `keep` (una entrada del grupo): completa sus campos vacíos con los de las demás, conserva la
        fecha de creación más antigua y borra el resto (con lápida, para que el borrado llegue al móvil)."""
        others = [e for e in group if e is not keep]
        for o in others:
            if not keep.get("alias") and o.get("alias"):
                keep["alias"] = o["alias"]
            n = (o.get("notes") or "").strip()
            if n and n not in (keep.get("notes") or ""):
                keep["notes"] = ((keep.get("notes") or "") + ("\n" if keep.get("notes") else "") + n).strip()
        created = [e["created"] for e in group if e.get("created")]
        if created:
            keep["created"] = min(created)
        keep["modified"], keep["rev"] = now_iso(), now_rev()
        ids = [o["id"] for o in others]
        self.vault.remove(section, ids)
        for i in ids:
            self.vault.data["webcheck"].pop(i, None)
        self.vault.save()
        return len(ids)

    def show_duplicates(self, section):
        dlg = tk.Toplevel(self, bg=PANEL)
        dlg.title("Entradas duplicadas")
        dlg.geometry(f"720x560+{self.winfo_rootx() + 120}+{self.winfo_rooty() + 40}")
        dlg.transient(self)
        picks = {}  # id del grupo -> IntVar con la posición de la entrada que se conserva
        body = tk.Frame(dlg, bg=PANEL)

        def newest(group):
            return max(range(len(group)), key=lambda i: group[i].get("rev", ""))

        def render():
            for w in dlg.winfo_children():
                w.destroy()
            groups = find_duplicates(self.vault.data[section], section)
            tk.Label(dlg, text="🧩  Entradas duplicadas", bg=PANEL, fg=TEXT, font=("Segoe UI Emoji", 15, "bold")).pack(
                anchor="w", padx=24, pady=(20, 0))
            tk.Label(dlg, text=("Elige cuál conservar en cada grupo (por defecto, la más reciente). Se completan sus "
                                "campos vacíos con los de las demás y se borran las otras."
                                if groups else "✅ No hay entradas duplicadas."),
                     bg=PANEL, fg=MUTED if groups else OK, font=("Segoe UI Emoji", 10), wraplength=660,
                     justify="left").pack(anchor="w", padx=24, pady=(4, 10))
            foot = tk.Frame(dlg, bg=PANEL)
            foot.pack(side="bottom", fill="x", padx=24, pady=14)
            if groups:
                button(foot, f"Fusionar los {len(groups)} grupos", lambda: merge_all(groups)).pack(side="left")
            button(foot, "Cerrar", close, primary=False).pack(side="left", padx=10)
            if not groups:
                return
            wrap = tk.Frame(dlg, bg=PANEL)
            wrap.pack(fill="both", expand=True, padx=(24, 12))
            cv = tk.Canvas(wrap, bg=PANEL, highlightthickness=0)
            sb = tk.Scrollbar(wrap, orient="vertical", command=cv.yview)
            inner = tk.Frame(cv, bg=PANEL)
            win = cv.create_window((0, 0), window=inner, anchor="nw")
            cv.configure(yscrollcommand=sb.set)
            inner.bind("<Configure>", lambda e: cv.configure(scrollregion=cv.bbox("all")))
            cv.bind("<Configure>", lambda e: cv.itemconfig(win, width=e.width))
            cv.bind_all("<MouseWheel>", lambda e: cv.yview_scroll(int(-e.delta / 120), "units"))
            cv.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            for g in groups:
                key = id(g[0])
                var = picks.setdefault(key, tk.IntVar(value=newest(g)))
                var.set(min(var.get(), len(g) - 1))
                card = tk.Frame(inner, bg=PANEL2, highlightthickness=1, highlightbackground=LINE)
                card.pack(fill="x", pady=6, padx=(0, 16))
                diff = len({e["pass"] for e in g}) > 1
                title = host_of(g[0]["user"]) if section == "webs" else g[0]["user"]
                tk.Label(card, text=f"{title}  ·  {len(g)} entradas" + ("   ⚠ con contraseñas distintas" if diff else ""),
                         bg=PANEL2, fg=WARN if diff else TEXT, font=("Segoe UI Emoji", 11, "bold")).pack(
                    anchor="w", padx=14, pady=(10, 4))
                for pos, e in enumerate(g):
                    lvl, word = strength(e["pass"])
                    when = e.get("modified") or e.get("created")
                    txt = (f"{short(e['user'], 40)}" + (f"   👤 {short(e['alias'], 28)}" if e.get("alias") else "")
                           + f"\n{'modificada' if e.get('modified') else 'creada'} {format_date(when) if when else 'sin fecha'}"
                           + f"  ·  contraseña {word.lower()}")
                    tk.Radiobutton(card, text=txt, variable=var, value=pos, bg=PANEL2, fg=TEXT, selectcolor=PANEL,
                                   activebackground=PANEL2, activeforeground=TEXT, anchor="w", justify="left",
                                   font=("Segoe UI Emoji", 10), cursor="hand2").pack(fill="x", padx=14, pady=2)
                button(card, "Fusionar este grupo", lambda g=g, v=var: merge_one(g, v.get())).pack(
                    anchor="w", padx=14, pady=(6, 12))

        def merge_one(group, pos):
            n = self.merge_group(section, group, group[pos])
            self.toast(f"Fusionadas: se borraron {n} entrada{'s' if n != 1 else ''} repetida{'s' if n != 1 else ''}")
            render()

        def merge_all(groups):
            total = 0
            for g in groups:  # cada grupo conserva la entrada elegida (por defecto, la más reciente)
                total += self.merge_group(section, g, g[min(picks[id(g[0])].get(), len(g) - 1)])
            self.toast(f"Fusionadas: se borraron {total} entrada{'s' if total != 1 else ''} repetida{'s' if total != 1 else ''}")
            render()

        def close():
            dlg.destroy()
            self.show_list()  # repinta la lista (y recupera la rueda del ratón)

        dlg.protocol("WM_DELETE_WINDOW", close)
        render()

    def show_generator(self):
        """Genera una contraseña segura (la misma lógica que la sugerencia al añadir), la copia al portapapeles
        y la muestra junto a un mensaje de confirmación."""
        dlg = tk.Toplevel(self, bg=PANEL, padx=34, pady=26)
        dlg.title("Generador de contraseñas")
        dlg.resizable(False, False)
        dlg.transient(self)
        self.update_idletasks()
        dlg.geometry(f"+{self.winfo_rootx() + 190}+{self.winfo_rooty() + 110}")
        tk.Label(dlg, text="🎲  Generador de contraseñas", bg=PANEL, fg=TEXT,
                 font=("Segoe UI Emoji", 15, "bold")).pack(anchor="w")
        status = tk.Label(dlg, text="", bg=PANEL, fg=OK, font=("Segoe UI Emoji", 11, "bold"), anchor="w")
        status.pack(anchor="w", pady=(10, 8))
        box = tk.Frame(dlg, bg=BG, highlightthickness=1, highlightbackground=ACCENT)
        box.pack(fill="x")
        shown = tk.Label(box, text="", bg=BG, fg=PASSC, font=("Consolas", 18, "bold"), padx=22, pady=14)
        shown.pack()
        meter, update_meter = strength_meter(dlg)
        meter.pack(anchor="w", pady=(10, 0))
        tk.Label(dlg, text="Se borra del portapapeles a los 30 segundos. Contraseña de 16 caracteres con "
                           "minúsculas, mayúsculas, números y símbolos.", bg=PANEL, fg=MUTED,
                 font=("Segoe UI", 9), wraplength=420, justify="left").pack(anchor="w", pady=(8, 14))
        state = {"pw": ""}

        def copy_current():
            self.clipboard_clear()
            self.clipboard_append(state["pw"])
            self.after(30000, self.clear_clipboard, state["pw"])
            status.config(text="✔  Contraseña copiada al portapapeles: ya puedes pegarla donde quieras")

        def make(_=None):
            state["pw"] = generate_password()
            shown.config(text=state["pw"])
            update_meter(state["pw"])
            copy_current()

        bar = tk.Frame(dlg, bg=PANEL)
        bar.pack(anchor="w")
        button(bar, "↻  Generar otra", make).pack(side="left")
        button(bar, "📋  Copiar de nuevo", copy_current, primary=False).pack(side="left", padx=10)
        button(bar, "Cerrar", dlg.destroy, primary=False).pack(side="left")
        dlg.bind("<Escape>", lambda e: dlg.destroy())
        dlg.bind("<Return>", make)
        dlg.focus_force()
        make()

    def ensure_deny_key(self):
        """Par de claves del registro de accesos denegados: la privada vive en el almacén cifrado y la pública en
        la configuración, así un intento fallido se puede registrar cifrado sin conocer la contraseña maestra."""
        d = self.vault.data
        if not d.get("denykey"):
            d["denykey"], _ = deny_keypair()
            self.vault.save()
        pub = pub_from_priv(d["denykey"])
        if self.cfg.get("deny_pub") != pub:
            self.cfg["deny_pub"] = pub
            save_cfg(self.cfg)
        denied_migrate(pub)  # intentos anteriores a tener clave: ya con su contraseña, cifrados

    def show_denied(self):
        self.in_form = False
        self.clear(self.main)
        self.unbind("<Return>")
        self.unbind("<Escape>")
        self.unbind_all("<MouseWheel>")
        self.cfg["denied_seen"] = now_iso()
        save_cfg(self.cfg)
        self.refresh_nav()
        self.header("Accesos denegados", "Intentos de desbloqueo con una contraseña incorrecta, del más reciente al más antiguo")
        rows = read_denied(self.vault.data.get("denykey", ""))
        warn = tk.Frame(self.main, bg=PANEL2, highlightthickness=1, highlightbackground=LINE)
        warn.pack(fill="x", padx=30, pady=(0, 8))
        tk.Label(warn, text="⚠  Las contraseñas de este registro son intentos fallidos y pueden parecerse a la real. "
                            "Se guardan cifradas y solo se ven con la app desbloqueada; bórralas cuando las hayas revisado. "
                            "La IP y la ubicación (aproximada) salen del equipo desde el que se intentó entrar.",
                 bg=PANEL2, fg=MUTED, font=("Segoe UI Emoji", 9), wraplength=640, justify="left", anchor="w").pack(
            fill="x", padx=14, pady=6)
        top = tk.Frame(self.main, bg=PANEL)
        top.pack(fill="x", padx=30, pady=(0, 6))
        tk.Label(top, text=(f"{len(rows)} intento{'s' if len(rows) != 1 else ''} registrado{'s' if len(rows) != 1 else ''}"
                            if rows else "✅ No hay ningún intento fallido registrado."),
                 bg=PANEL, fg=DANGER if rows else OK, font=("Segoe UI Emoji", 11, "bold")).pack(side="left")

        def clear_log():
            if rows and messagebox.askyesno("Borrar registro", "¿Borrar todos los intentos registrados? No se puede deshacer.",
                                            icon="warning", parent=self):
                stamp = now_rev()
                for e in denied_load():  # lápidas: el borrado también llega al otro dispositivo
                    if e.get("id"):
                        self.vault.data["deleted"][e["id"]] = stamp
                denied_clear()
                self.vault.save()
                self.show_denied()

        button(top, "Borrar registro", clear_log, danger=True).pack(side="right")
        button(top, "Actualizar", self.show_denied, primary=False).pack(side="right", padx=8)

        st = ttk.Style(self)
        st.theme_use("clam")
        st.configure("G.Treeview", background=PANEL2, fieldbackground=PANEL2, foreground=TEXT, rowheight=30,
                     borderwidth=0, font=("Segoe UI Emoji", 10))
        st.configure("G.Treeview.Heading", background=PANEL, foreground=MUTED, font=("Segoe UI", 9, "bold"),
                     borderwidth=0, relief="flat")
        st.map("G.Treeview", background=[("selected", ACCENT)], foreground=[("selected", "white")])
        st.map("G.Treeview.Heading", background=[("active", PANEL)])
        st.configure("Vertical.TScrollbar", background=LINE, troughcolor=PANEL, arrowcolor=MUTED, borderwidth=0)
        box = tk.Frame(self.main, bg=PANEL)
        box.pack(fill="both", expand=True, padx=(30, 12), pady=(0, 8))
        cols = (("fecha", "FECHA Y HORA", 140), ("pw", "CONTRASEÑA INTRODUCIDA", 170), ("ip", "IP", 150),
                ("loc", "UBICACIÓN", 200), ("dev", "DISPOSITIVO", 230))
        tree = ttk.Treeview(box, style="G.Treeview", columns=[c[0] for c in cols], show="headings", selectmode="browse")
        for key, text, w in cols:
            tree.heading(key, text=text, anchor="w")
            tree.column(key, width=w, stretch=key == "dev", anchor="w")
        tree.tag_configure("bad", foreground=DANGER)
        vsb = ttk.Scrollbar(box, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        for r in rows:
            ip = r.get("ip", "") or "—"
            if r.get("lan"):
                ip += f"  (red local {r['lan']})"
            tree.insert("", "end", tags=("bad",), values=(
                format_date(r["t"]), r["pw"] if r.get("pw") is not None else "(no registrada)", ip,
                r.get("loc") or "—", r.get("dev", "")))

    def show_changelog(self):
        self.in_form = False
        self.clear(self.main)
        self.unbind("<Return>")
        self.unbind("<Escape>")
        self.refresh_nav()
        self.header("Changelog", f"Versión {APP_VERSION}  ·  todo lo que se ha ido añadiendo, de lo más nuevo a lo más antiguo")
        canvas, box = scroll_area(self.main)
        for version, date, title, items in CHANGELOG:
            card = tk.Frame(box, bg=PANEL2, highlightthickness=1, highlightbackground=ACCENT if version == APP_VERSION else LINE)
            card.pack(fill="x", pady=6, padx=(0, 16))
            head = tk.Frame(card, bg=PANEL2)
            head.pack(fill="x", padx=16, pady=(12, 4))
            tk.Label(head, text=f"v{version}", bg=ACCENT, fg="white", font=("Segoe UI", 10, "bold"),
                     padx=8, pady=1).pack(side="left")
            tk.Label(head, text=title, bg=PANEL2, fg=TEXT, font=("Segoe UI", 12, "bold")).pack(side="left", padx=10)
            tk.Label(head, text=date, bg=PANEL2, fg=MUTED, font=("Segoe UI", 10)).pack(side="right")
            for item in items:
                tk.Label(card, text="•  " + item, bg=PANEL2, fg=MUTED if not item.startswith("📜") else TEXT,
                         font=("Segoe UI Emoji", 10), wraplength=600, justify="left", anchor="w").pack(
                    fill="x", padx=(18, 16), pady=2)
            tk.Frame(card, bg=PANEL2, height=8).pack()

    def header(self, title, sub):
        tk.Label(self.main, text=title, bg=PANEL, fg=TEXT, font=("Segoe UI", 20, "bold"),
                 anchor="w").pack(fill="x", padx=30, pady=(26, 0))
        lbl = tk.Label(self.main, text=sub, bg=PANEL, fg=MUTED, font=("Segoe UI", 10), anchor="w")
        lbl.pack(fill="x", padx=30, pady=(0, 10))
        return lbl

    # --- Lista ---
    def show_list(self):
        self.in_form = False
        if self.vault.migrate():  # red de seguridad: toda entrada debe tener id/rev para sincronizar y comprobar
            self.vault.save()
        self.clear(self.main)
        self.unbind("<Return>")
        self.unbind("<Escape>")
        self.refresh_nav()
        s = SECTIONS[self.current]
        items = self.vault.data[self.current]

        # avisos de seguridad: contraseñas repetidas (en todo el almacén) y antiguas
        counts = Counter(e["pass"] for k in SECTIONS for e in self.vault.data[k])
        n_rep = sum(1 for e in items if counts[e["pass"]] > 1)
        n_old = sum(1 for e in items if is_old(e))
        sub = s["sub"]
        if n_rep:
            sub += f"   ·   ⚠ {n_rep} con contraseña repetida"
        if n_old:
            sub += f"   ·   ⏳ {n_old} sin cambiar desde hace más de un año"
        sublabel = self.header(s["title"], sub)
        if n_rep or n_old:
            sublabel.config(fg=WARN)

        # Botón abajo (se empaqueta antes para que siempre quede visible)
        foot = tk.Frame(self.main, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        foot.pack(side="bottom", fill="x")
        button(foot, "+  Añadir", self.show_form).pack(side="right", padx=30, pady=14)

        # Buscador (en directo), orden y filtro de repetidas
        bar = tk.Frame(self.main, bg=PANEL)
        bar.pack(fill="x", padx=30, pady=(0, 10))
        tk.Label(bar, text="🔍", bg=PANEL, fg=MUTED, font=("Segoe UI Emoji", 12)).pack(side="left")
        query = tk.StringVar(value=self.query)
        search = entry(bar)
        search.config(textvariable=query, width=6)  # ancho mínimo pequeño: se estira con el espacio libre y deja sitio a los botones
        search.pack(side="left", fill="x", expand=True, ipady=7, padx=(8, 0))
        clear_q = tk.Label(bar, text="✕", bg=PANEL, fg=MUTED, font=("Segoe UI", 11), cursor="hand2", padx=8)
        clear_q.bind("<Button-1>", lambda e: (query.set(""), search.focus_set()))
        clear_q.pack(side="left")
        bar.pack_configure(pady=(0, 6))
        bar2 = tk.Frame(self.main, bg=PANEL)  # segunda fila: contador y botones (así caben en ventanas estrechas)
        bar2.pack(fill="x", padx=30, pady=(0, 10))
        found = tk.Label(bar2, text="", bg=PANEL, fg=MUTED, font=("Segoe UI", 10), width=11, anchor="w")
        found.pack(side="left")
        sort_btn = tk.Label(bar2, text="", bg=PANEL2, fg=TEXT, font=("Segoe UI", 10), cursor="hand2", padx=8, pady=6,
                            highlightthickness=1, highlightbackground=LINE)
        sort_btn.pack(side="left", padx=(8, 0))
        add_tooltip(sort_btn, "Cambiar el orden de la lista")
        chk_btn = None
        if self.current == "webs":  # comprobar si las webs guardadas siguen en funcionamiento
            chk_btn = tk.Label(bar2, text="", bg=PANEL2, fg=TEXT, font=("Segoe UI Emoji", 10), cursor="hand2",
                               padx=8, pady=6, highlightthickness=1, highlightbackground=LINE)
            chk_btn.pack(side="left", padx=(6, 0))
            add_tooltip(chk_btn, "Comprueba si cada web guardada sigue en funcionamiento; las que no, se marcan en rojo")
        dup_btn = tk.Label(bar2, text=f"⚠ Repetidas ({n_rep})", bg=PANEL2, fg=TEXT, font=("Segoe UI Emoji", 10),
                           cursor="hand2", padx=8, pady=6, highlightthickness=1, highlightbackground=LINE)
        dup_btn.pack(side="left", padx=(6, 0))
        add_tooltip(dup_btn, "Mostrar solo las entradas cuya contraseña está repetida")
        n_dups = len(find_duplicates(items, self.current))
        dups_btn = tk.Label(bar2, text=f"🧩 Duplicadas ({n_dups})", bg=DANGER if n_dups else PANEL2,
                            fg="white" if n_dups else TEXT, font=("Segoe UI Emoji", 10), cursor="hand2", padx=8, pady=6,
                            highlightthickness=1, highlightbackground=LINE)
        dups_btn.pack(side="left", padx=(6, 0))
        add_tooltip(dups_btn, "Entradas repetidas (misma web y usuario, o mismo correo): revisarlas y fusionarlas")
        dups_btn.bind("<Button-1>", lambda e: self.show_duplicates(self.current))
        flags = self.breach_flags(self.current)  # {índice: [motivos]} de lo que aparece en la sección Brechas
        brk_btn = tk.Label(bar2, text=f"❗ Brechas ({len(flags)})", bg=PANEL2, fg=TEXT, font=("Segoe UI Emoji", 10),
                           cursor="hand2", padx=8, pady=6, highlightthickness=1, highlightbackground=LINE)
        brk_btn.pack(side="left", padx=(6, 0))
        add_tooltip(brk_btn, "Mostrar u ocultar los símbolos rojos ❗ de las entradas que aparecen en brechas")

        # La lista se dibuja sobre un único Canvas (en vez de ~15 widgets por fila): con cientos de
        # entradas, crear miles de widgets de Tk hacía lenta la aplicación.
        wrap = tk.Frame(self.main, bg=PANEL)
        wrap.pack(fill="both", expand=True, padx=(30, 12))
        canvas = tk.Canvas(wrap, bg=PANEL, highlightthickness=0)
        sb = tk.Scrollbar(wrap, orient="vertical", command=canvas.yview)
        canvas.configure(yscrollcommand=sb.set)
        canvas.bind_all("<MouseWheel>", lambda e: canvas.yview_scroll(int(-e.delta / 120), "units"))
        canvas.pack(side="left", fill="both", expand=True)
        sb.pack(side="right", fill="y")

        tooltip = Tooltip(canvas)
        view = {"shown": [], "hover": None, "w": 0, "pass_chars": 12, "down": {}}

        def calc_down():
            """{índice: (motivo, fecha)} de las webs que la última comprobación dio por no disponibles."""
            wc = self.vault.data["webcheck"]
            return {i: (wc[e["id"]].get("why", ""), wc[e["id"]].get("t", "")) for i, e in enumerate(items)
                    if self.current == "webs" and e["id"] in wc and wc[e["id"]].get("ok") is False}

        view["down"] = calc_down()
        revealed = set()  # índices con la contraseña visible (se conservan al redibujar)
        pass_items = {}
        selected = set()  # índices marcados para eliminar en bloque

        # barra de selección (a la izquierda del botón Añadir); solo visible si hay algo marcado
        selbar = tk.Frame(foot, bg=PANEL)
        sel_label = tk.Label(selbar, text="", bg=PANEL, fg=TEXT, font=("Segoe UI", 10, "bold"))
        sel_label.pack(side="left", padx=(0, 12))
        button(selbar, "🗑  Eliminar seleccionadas", lambda: delete_selected(), danger=True).pack(side="left")
        button(selbar, "Deseleccionar", lambda: clear_selection(), primary=False).pack(side="left", padx=8)

        def update_selbar():
            if selected:
                n = len(selected)
                sel_label.config(text=f"{n} seleccionada" + ("" if n == 1 else "s"))
                selbar.pack(side="left", padx=30, pady=14)
            else:
                selbar.pack_forget()

        def clear_selection():
            selected.clear()
            draw()
            update_selbar()

        def toggle_check(key):
            tooltip.hide()
            visible = {i for i, _ in view["shown"]}
            if key == "all":
                if visible and selected >= visible:
                    selected.clear()
                else:
                    selected.update(visible)
            else:
                selected.symmetric_difference_update({int(key)})
            draw()
            update_selbar()

        def delete_selected():
            n = len(selected)
            if not n:
                return
            if messagebox.askyesno("Eliminar", f"¿Eliminar {n} {'entrada' if n == 1 else 'entradas'} de "
                                   f"{s['title']}?\nEsta acción no se puede deshacer.", icon="warning", parent=self):
                self.vault.remove(self.current, [items[i]["id"] for i in selected])
                self.vault.save()
                self.show_list()
                self.toast(f"{n} eliminadas" if n != 1 else "1 eliminada")

        def draw_check(x, y, state, bg, tag):
            """Casilla de verificación; state: 'none' | 'some' | 'all'."""
            on = state != "none"
            canvas.create_rectangle(x - 14, y - 14, x + 14, y + 14, fill=bg, outline="", tags=("chk", tag))
            canvas.create_rectangle(x - 8, y - 8, x + 8, y + 8, fill=ACCENT if on else bg,
                                    outline=ACCENT if on else MUTED, width=2, tags=("chk", tag))
            if on:
                canvas.create_text(x, y, text="✓" if state == "all" else "–", fill="white",
                                   font=("Segoe UI", 10, "bold"), tags=("chk", tag))

        def actions_for(i, it):
            acts = []
            if self.current == "webs":
                acts.append(("open", "↗", "Abrir la web en el navegador"))
            if it.get("notes"):
                acts.append(("notes", "📝", "Ver las notas"))
            acts += [("eye", "👁", "Mostrar u ocultar la contraseña"),
                     ("copy", "📋", "Copiar la contraseña (se borra del portapapeles a los 30 s)"),
                     ("edit", "✏", "Editar esta entrada"), ("del", "🗑", "Eliminar esta entrada")]
            return acts

        def pass_text(i, it):
            """Contraseña oculta (puntos) o visible, recortada con «…» si no cabe en su columna."""
            if i not in revealed:
                return "•" * min(len(it["pass"]), 12)
            n = view.get("pass_chars", 12)
            return it["pass"] if len(it["pass"]) <= n else it["pass"][:n - 1] + "…"

        def draw(*_):
            W = canvas.winfo_width()
            if W < 100:
                return
            view["w"], view["hover"] = W, None
            tooltip.hide()
            canvas.delete("all")
            pass_items.clear()
            shown = view["shown"]
            if not shown:
                if not items:
                    text = "📭\n\nAún no hay nada guardado.\nPulsa «Añadir» para empezar."
                elif self.only_dups and not self.query.strip():
                    text = "✅\n\nNo hay contraseñas repetidas."
                else:
                    text = f"🔎\n\nNingún resultado para «{self.query.strip()}»"
                canvas.create_text(W / 2, 110, text=text, fill=MUTED, font=("Segoe UI Emoji", 12), justify="center")
                canvas.configure(scrollregion=(0, 0, W, 10))
                return
            R = W - 8
            date_x = R - 12 - 190 - 150
            # la columna de contraseña crece con la ventana (125–300 px); si no cabe, se recorta con «…»
            pass_w = max(125, min(300, date_x - 14 - 230))
            pass_x = date_x - pass_w
            view["pass_chars"] = (pass_w - 14) // 9
            user_chars = max(10, (pass_x - 100) // 8)  # deja sitio al símbolo ❗ de brechas
            TX = 44  # los textos empiezan tras la casilla de selección
            visible = {i for i, _ in shown}
            draw_check(22, 14, "all" if selected >= visible else "some" if selected else "none", PANEL, "chk:all")
            canvas.create_text(TX, 14, text=s["field"].upper(), anchor="w", fill=MUTED, font=("Segoe UI", 9, "bold"))
            canvas.create_text(pass_x, 14, text="CONTRASEÑA", anchor="w", fill=MUTED, font=("Segoe UI", 9, "bold"))
            canvas.create_text(date_x, 14, text="CREADO / MODIFICADO", anchor="w", fill=MUTED, font=("Segoe UI", 9, "bold"))
            for n, (i, it) in enumerate(shown):
                y0 = HEAD_H + n * ROW_H
                mid = y0 + ROW_H / 2
                canvas.create_rectangle(0, y0 + 3, R, y0 + ROW_H - 3, fill=PANEL2,
                                        outline=ACCENT if i in selected else LINE, width=2 if i in selected else 1)
                draw_check(22, mid, "all" if i in selected else "none", PANEL2, f"chk:{i}")
                dead = i in view["down"]  # web que ya no responde: dirección en rojo
                ucol, utags = (DANGER, ("wk", f"wk:{i}")) if dead else (TEXT, ())
                if it.get("alias"):
                    canvas.create_text(TX, mid - 9, text=short(it["user"], user_chars), anchor="w", fill=ucol,
                                       font=FONT, tags=utags)
                    canvas.create_text(TX, mid + 11, text="👤 " + short(it["alias"], user_chars + 4), anchor="w",
                                       fill=MUTED, font=("Segoe UI Emoji", 9))
                else:
                    canvas.create_text(TX, mid, text=short(it["user"], user_chars), anchor="w", fill=ucol,
                                       font=FONT, tags=utags)
                if i in flags and self.cfg["show_breach_marks"]:  # ❗ rojo: aparece en la sección Brechas
                    bx = pass_x - 22
                    canvas.create_oval(bx - 10, mid - 10, bx + 10, mid + 10, fill=DANGER, outline="",
                                       tags=("brk", f"brk:{i}"))
                    canvas.create_text(bx, mid, text="!", fill="white", font=("Segoe UI", 12, "bold"),
                                       tags=("brk", f"brk:{i}"))
                pass_items[i] = canvas.create_text(
                    pass_x, mid - 8, anchor="w", fill=PASSC, font=("Consolas", 11), tags=("pw", f"pw:{i}"),
                    text=pass_text(i, it))
                # fortaleza junto a la contraseña: barra de 4 tramos y el nivel
                lvl, word = strength(it["pass"])
                scol = strength_colors()[lvl]
                for k in range(4):
                    canvas.create_rectangle(pass_x + k * 12, mid + 8, pass_x + k * 12 + 10, mid + 12,
                                            fill=scol if k < lvl else LINE, outline="")
                canvas.create_text(pass_x + 52, mid + 10, text=word, anchor="w", fill=scol, font=("Segoe UI", 8, "bold"))
                small = ("Segoe UI Emoji", 9)
                lines = []  # (texto, color, fuente)
                if it.get("created"):
                    lines.append((format_date(it["created"]), MUTED, ("Segoe UI", 10)))
                elif not it.get("modified"):
                    lines.append(("Sin fecha", MUTED, ("Segoe UI", 10)))
                # sin fecha de creación conocida, la de modificación sustituye al aviso «Sin fecha»
                if it.get("modified"):
                    lines.append(("✏ " + format_date(it["modified"]), MUTED, small))
                if counts[it["pass"]] > 1:
                    lines.append(("⚠ repetida", WARN, small))
                if is_old(it):
                    lines.append(("⏳ +1 año", WARN, small))
                top = mid - (len(lines) - 1) * 7.5  # el bloque de fechas queda centrado en la fila, como la contraseña
                for k, (text, color, font) in enumerate(lines):
                    canvas.create_text(date_x, top + k * 15, text=text, anchor="w", fill=color, font=font)
                acts = actions_for(i, it)
                for k, (name, glyph, _tip) in enumerate(acts):
                    cx = R - 12 - (len(acts) - k) * 30 + 15
                    tag = f"act:{i}:{name}"
                    canvas.create_rectangle(cx - 14, mid - 14, cx + 14, mid + 14, fill=PANEL2, outline="",
                                            tags=("act", tag))
                    canvas.create_text(cx, mid, text=glyph, fill=DANGER if name == "del" else MUTED,
                                       font=("Segoe UI Emoji", 12), tags=("act", tag, "glyph"))
            canvas.configure(scrollregion=(0, 0, W, HEAD_H + len(shown) * ROW_H + 6))

        def act_under_pointer():
            ids = canvas.find_withtag("current")
            for t in (canvas.gettags(ids[0]) if ids else ()):
                if t.startswith("act:"):
                    _, i, name = t.split(":")
                    return t, int(i), name
            return None

        def on_motion(e):
            hit = act_under_pointer()
            tag, pw_i, chk_tag, brk_i, wk_i = (hit[0] if hit else None), None, None, None, None
            if not hit:
                ids = canvas.find_withtag("current")
                for t in (canvas.gettags(ids[0]) if ids else ()):
                    if t.startswith("chk:"):
                        tag = chk_tag = t
                    elif t.startswith("brk:"):
                        tag, brk_i = t, int(t[4:])
                    elif t.startswith("wk:"):
                        tag, wk_i = t, int(t[3:])
                    # contraseña visible y recortada: al pasar el cursor se muestra completa
                    elif t.startswith("pw:") and int(t[3:]) in revealed \
                            and len(items[int(t[3:])]["pass"]) > view["pass_chars"]:
                        tag, pw_i = t, int(t[3:])
            if tag == view["hover"]:
                return
            old = view["hover"]
            if old:  # restaurar el color del icono anterior
                for item in canvas.find_withtag(old):
                    if "glyph" in canvas.gettags(item):
                        canvas.itemconfig(item, fill=DANGER if old.endswith(":del") else MUTED)
            view["hover"] = tag
            tooltip.hide()
            if hit:
                canvas.config(cursor="hand2")
                for item in canvas.find_withtag(tag):
                    if "glyph" in canvas.gettags(item):
                        canvas.itemconfig(item, fill=DANGER if hit[2] == "del" else TEXT)
                text = next(t for n_, _g, t in actions_for(hit[1], items[hit[1]]) if n_ == hit[2])
                tooltip.schedule(text, e.x_root, e.y_root)
            else:
                canvas.config(cursor="hand2" if chk_tag else "")
                if chk_tag:
                    tooltip.schedule("Marcar / desmarcar todas las mostradas" if chk_tag == "chk:all"
                                     else "Seleccionar para eliminar varias a la vez", e.x_root, e.y_root)
                elif wk_i is not None and wk_i in view["down"]:
                    why, when = view["down"][wk_i]
                    tooltip.schedule(f"✖ Web no disponible: {why}\nComprobada el {format_date(when)}",
                                     e.x_root, e.y_root)
                elif brk_i is not None and brk_i in flags:
                    tooltip.schedule("❗ Aparece en brechas de seguridad:\n" + "\n".join(flags[brk_i]),
                                     e.x_root, e.y_root)
                elif pw_i is not None:
                    tooltip.schedule(items[pw_i]["pass"], e.x_root, e.y_root)

        def on_motion_none():
            old = view["hover"]
            if old:
                for item in canvas.find_withtag(old):
                    if "glyph" in canvas.gettags(item):
                        canvas.itemconfig(item, fill=DANGER if old.endswith(":del") else MUTED)
            view["hover"] = None
            tooltip.hide()
            canvas.config(cursor="")

        def on_click(_):
            ids = canvas.find_withtag("current")
            for t in (canvas.gettags(ids[0]) if ids else ()):
                if t.startswith("chk:"):
                    toggle_check(t[4:])
                    return
            hit = act_under_pointer()
            if not hit:
                return
            tooltip.hide()
            _, i, name = hit
            it = items[i]
            if name == "open":
                open_web(self, it["user"])
            elif name == "notes":
                messagebox.showinfo("Notas", f"{it['user']}\n\n{it['notes']}", parent=self)
            elif name == "eye":
                revealed.symmetric_difference_update({i})
                if i in pass_items:
                    canvas.itemconfig(pass_items[i], text=pass_text(i, it))
            elif name == "copy":
                self.copy(it["pass"])
            elif name == "edit":
                self.show_form(i)
            elif name == "del":
                self.delete(i)

        canvas.bind("<Motion>", on_motion)
        canvas.bind("<Leave>", lambda e: on_motion_none())
        canvas.bind("<Button-1>", on_click)
        resize_job = [None]

        def on_resize(e):
            if resize_job[0]:
                canvas.after_cancel(resize_job[0])
            if e.width != view["w"]:
                resize_job[0] = canvas.after(60, draw)

        canvas.bind("<Configure>", on_resize)

        def render(*_):
            self.query = query.get()
            q = self.query.strip().lower()
            canvas.yview_moveto(0)
            sort_btn.config(text=f"⇅  {SORTS[self.sort]}")
            dup_btn.config(bg=WARN if self.only_dups else PANEL2, fg="#1b1e3a" if self.only_dups else TEXT)
            # se conserva el índice original para que editar/borrar funcione con filtro y orden
            shown = [(i, it) for i, it in enumerate(items)
                     if q in (it["user"] + "\n" + it.get("alias", "") + "\n" + it.get("notes", "") + "\n"
                              + it["pass"]).lower()
                     and (not self.only_dups or counts[it["pass"]] > 1)]
            mode = SORTS[self.sort]
            if self.only_dups:  # las que comparten contraseña quedan juntas
                shown.sort(key=lambda t: (t[1]["pass"], t[1]["user"].lower()))
            elif mode in ("Más recientes", "Más antiguas"):
                shown.sort(key=lambda t: t[1].get("created") or t[1].get("modified") or "",
                           reverse=mode == "Más recientes")
            else:
                shown.sort(key=lambda t: t[1]["user"].lower(), reverse=mode == "Z–A")
            found.config(text=f"{len(shown)} de {len(items)}" if (q or self.only_dups) else f"{len(items)} en total")
            view["shown"] = shown
            selected.intersection_update(i for i, _ in shown)  # nunca queda marcado algo que no se ve
            update_selbar()
            draw()

        def cycle_sort(_=None):
            self.sort = (self.sort + 1) % len(SORTS)
            render()

        def style_brk():
            on = self.cfg["show_breach_marks"]
            brk_btn.config(bg=DANGER if on else PANEL2, fg="white" if on else TEXT)

        def toggle_marks(_=None):
            self.cfg["show_breach_marks"] = not self.cfg["show_breach_marks"]
            save_cfg(self.cfg)
            style_brk()
            draw()  # solo se redibuja: no se pierde la posición ni el filtro

        def chk_refresh():
            """Texto y color del botón «Comprobar webs» según el estado; redibuja al terminar."""
            if chk_btn is None or not chk_btn.winfo_exists():
                return
            st = self.webcheck
            view["down"] = calc_down()
            n = len(view["down"])
            wide = self.winfo_width() >= 1040  # con la ventana más estrecha se usa el texto corto
            checked = any(e["id"] in self.vault.data["webcheck"] for e in items)
            if st:
                chk_btn.config(text=f"⏳ Comprobando {st['done']}/{st['total']}… (cancelar)", bg=ACCENT, fg="white")
            elif not checked:
                chk_btn.config(text="🌐 Comprobar webs", bg=PANEL2, fg=TEXT)
            elif n:
                tail = f"{n} no disponible{'s' if n != 1 else ''}" if wide else f"{n} caída{'s' if n != 1 else ''}"
                chk_btn.config(text=f"🌐 Comprobar webs · {tail}", bg=DANGER, fg="white")
            else:
                chk_btn.config(text="🌐 Comprobar webs · todas OK" if not wide else "🌐 Comprobar webs · todas funcionan",
                               bg=PANEL2, fg=OK)
            if not st:
                draw()

        def chk_click(_=None):
            if self.webcheck:  # ya en marcha: pulsar de nuevo cancela
                self.webcheck["cancel"].set()
                return
            self.start_webcheck([(e["id"], e["user"]) for e in items], chk_refresh)

        def toggle_dups(_=None):
            self.only_dups = not self.only_dups
            render()

        job = [None]

        def on_query(*_):
            # espera a que dejes de escribir (evita redibujar en cada tecla)
            if job[0]:
                self.after_cancel(job[0])
            job[0] = self.after(200, apply_query)

        def apply_query():
            if canvas.winfo_exists():  # puede haberse cambiado de pantalla mientras tanto
                render()

        sort_btn.bind("<Button-1>", cycle_sort)
        dup_btn.bind("<Button-1>", toggle_dups)
        brk_btn.bind("<Button-1>", toggle_marks)
        style_brk()
        if chk_btn is not None:
            chk_btn.bind("<Button-1>", chk_click)
            if self.webcheck:
                self.webcheck_ui = chk_refresh  # la comprobación sigue en marcha: reengancha el botón
            chk_refresh()
        query.trace_add("write", on_query)
        render()
        if self.query:
            search.focus_set()
            search.icursor("end")

    def breach_flags(self, sec):
        """{índice: [motivos]} de las entradas de `sec` que aparecen en la sección Brechas.
        Contraseña: por su hash (así se marca también si se edita o si otra entrada usa la misma).
        Correo: por la caché de correos comprobados (también entradas añadidas después)."""
        data = self.vault.data["brechas"]
        findings = data.get("findings", [])
        by_hash = {f["h"]: f.get("n", 0) for f in findings if f.get("type") == "pw" and f.get("h")}
        legacy = {f["user"] for f in findings if f.get("type") == "pw" and not f.get("h") and f.get("sec") == sec}
        mails = {em: v.get("b") for em, v in (data.get("emails") or {}).items() if isinstance(v, dict) and v.get("b")}
        flags = {}
        for i, e in enumerate(self.vault.data[sec]):
            why = []
            if by_hash or legacy:
                h = pw_hash(e["pass"])
                if h in by_hash:
                    n = by_hash[h]
                    why.append(f"Contraseña vista {n:,} veces en filtraciones".replace(",", ".") if n
                               else "Contraseña expuesta en filtraciones")
                elif e["user"] in legacy:
                    why.append("Contraseña expuesta en filtraciones")
            if mails and sec != "webs":  # en Webs el ❗ solo señala contraseñas expuestas; el correo se ve en Correos
                for m in sorted({m.lower() for m in EMAIL_RE.findall(e["user"] + " " + e.get("alias", ""))}):
                    names = mails.get(m)
                    if names:
                        why.append(f"Correo {m} en {len(names)} brechas: " + ", ".join(names[:5])
                                   + ("…" if len(names) > 5 else ""))
            if why:
                flags[i] = why
        return flags

    def copy(self, password):
        self.clipboard_clear()
        self.clipboard_append(password)
        self.toast("Contraseña copiada")
        self.after(30000, self.clear_clipboard, password)  # se borra sola a los 30 s

    def clear_clipboard(self, password):
        try:
            if self.clipboard_get() == password:
                self.clipboard_clear()
        except tk.TclError:
            pass

    def delete(self, index):
        it = self.vault.data[self.current][index]
        if messagebox.askyesno("Eliminar", f"¿Eliminar «{it['user']}»?", parent=self):
            self.vault.remove(self.current, [it["id"]])
            self.vault.save()
            self.show_list()

    def toast(self, text):
        t = tk.Label(self, text=text, bg=OK, fg="#05281a", font=("Segoe UI", 10, "bold"), padx=16, pady=8)
        t.place(relx=0.6, rely=0.93, anchor="center")
        self.after(1800, t.destroy)

    # --- Formulario de alta / edición ---
    def show_form(self, index=None):
        self.in_form = True  # una actualización desde el navegador no debe tirar el formulario abierto
        self.clear(self.main)
        self.unbind_all("<MouseWheel>")
        s = SECTIONS[self.current]
        old = self.vault.data[self.current][index] if index is not None else None
        self.header(f"Editar en {s['title']}" if old else f"Añadir a {s['title']}",
                    "Los campos con * son obligatorios")
        form = tk.Frame(self.main, bg=PANEL)
        form.pack(anchor="nw", padx=30, pady=4)
        form.columnconfigure(0, minsize=350)
        form.columnconfigure(1, minsize=320)

        def label(text, r, c):
            tk.Label(form, text=text, bg=PANEL, fg=MUTED, font=("Segoe UI", 10), anchor="w").grid(
                row=r, column=c, sticky="w", padx=(0, 0) if c == 0 else (20, 0))

        label(s["field"] + " *", 0, 0)
        user = entry(form)
        user.grid(row=1, column=0, sticky="ew", ipady=8, pady=(4, 12))
        label("Contraseña *", 2, 0)
        pw = entry(form)
        pw.grid(row=3, column=0, sticky="ew", ipady=8, pady=(4, 6))
        label("Usuario / alias (opcional)", 0, 1)
        alias = entry(form)
        alias.grid(row=1, column=1, sticky="ew", ipady=8, pady=(4, 12), padx=(20, 0))
        label("Notas (opcional)", 2, 1)
        notes = tk.Text(form, height=5, width=10, font=FONT, bg=BG, fg=TEXT, insertbackground=TEXT, relief="flat",
                        wrap="word", highlightthickness=1, highlightbackground=LINE, highlightcolor=ACCENT)
        notes.grid(row=3, column=1, rowspan=3, sticky="nsew", pady=(4, 0), padx=(20, 0))

        meter, update_meter = strength_meter(form)
        meter.grid(row=5, column=0, sticky="w", pady=(4, 0))

        # Interruptor: sugerir contraseña segura
        sug = tk.Frame(form, bg=PANEL)
        sug.grid(row=4, column=0, sticky="w", pady=(2, 0))
        state = {"on": False, "last": ""}
        sw = tk.Canvas(sug, width=44, height=24, bg=PANEL, highlightthickness=0, cursor="hand2")
        sw.pack(side="left")
        tk.Label(sug, text="Sugerir contraseña segura", bg=PANEL, fg=TEXT, font=("Segoe UI", 10)).pack(
            side="left", padx=10)
        regen = tk.Label(sug, text="↻ Otra", bg=PANEL, fg=ACCENT, font=("Segoe UI", 10, "bold"), cursor="hand2")

        def draw():
            sw.delete("all")
            col = ACCENT if state["on"] else LINE
            sw.create_oval(0, 0, 24, 24, fill=col, outline=col)
            sw.create_oval(20, 0, 44, 24, fill=col, outline=col)
            sw.create_rectangle(12, 0, 32, 24, fill=col, outline=col)
            x = 22 if state["on"] else 2
            sw.create_oval(x, 2, x + 20, 22, fill="white", outline="white")

        def suggest(_=None):
            state["last"] = generate_password()
            pw.delete(0, "end")
            pw.insert(0, state["last"])
            update_meter(state["last"])

        def flip(_=None):
            state["on"] = not state["on"]
            draw()
            if state["on"]:
                suggest()
                regen.pack(side="left", padx=6)
            else:
                regen.pack_forget()
                if pw.get() == state["last"]:  # solo se borra si sigue siendo la sugerida
                    pw.delete(0, "end")
                    update_meter("")

        sw.bind("<Button-1>", flip)
        regen.bind("<Button-1>", suggest)
        pw.bind("<KeyRelease>", lambda e: update_meter(pw.get()))
        draw()

        if old:
            user.insert(0, old["user"])
            pw.insert(0, old["pass"])
            alias.insert(0, old.get("alias", ""))
            notes.insert("1.0", old.get("notes", ""))
            update_meter(old["pass"])

        msg = tk.Label(form, text="", bg=PANEL, fg=DANGER, font=("Segoe UI", 10), anchor="w")
        msg.grid(row=6, column=0, columnspan=2, sticky="w", pady=(8, 0))
        user.focus_set()

        def accept(_=None):
            u, p = user.get().strip(), pw.get().strip()
            user.config(highlightbackground=DANGER if not u else LINE)
            pw.config(highlightbackground=DANGER if not p else LINE)
            if not u or not p:
                msg.config(text="Los campos obligatorios no pueden estar vacíos.")
                (user if not u else pw).focus_set()
                return
            data = {"user": u, "pass": p, "alias": alias.get().strip(), "notes": notes.get("1.0", "end").strip()}
            if old:
                if all(old.get(k, "") == v for k, v in data.items()):
                    self.show_list()  # no se tocó nada: no se registra modificación
                    return
                data["modified"] = now_iso()  # cualquier cambio guarda la fecha de modificación
                if p != old["pass"]:
                    data["changed"] = data["modified"]  # además reinicia el contador de antigüedad
                data["rev"] = now_rev()
                if self.current == "webs" and u != old["user"]:
                    self.vault.data["webcheck"].pop(old["id"], None)  # otra dirección: el resultado ya no vale
                old.update(data)
            else:
                stamp = now_iso()
                self.vault.data[self.current].append(
                    self.vault.new_entry({**data, "created": stamp, "changed": stamp}))
            self.vault.save()
            self.query, self.only_dups = "", False  # para que la entrada se vea aunque hubiera filtro
            self.show_list()
            self.toast("Guardado ✔")

        bar = tk.Frame(form, bg=PANEL)
        bar.grid(row=7, column=0, columnspan=2, sticky="w", pady=(6, 0))
        button(bar, "Aceptar", accept).pack(side="left")
        button(bar, "Cancelar", self.show_list, primary=False).pack(side="left", padx=10)
        for w in (user, pw, alias):
            w.bind("<Return>", accept)  # en Notas, Enter es salto de línea
        self.bind("<Escape>", lambda e: self.show_list())

    # --- Brechas de seguridad ---
    def show_breach(self):
        self.in_form = False
        self.clear(self.main)
        self.unbind("<Return>")
        self.unbind("<Escape>")
        self.unbind_all("<MouseWheel>")
        self.refresh_nav()
        self.header("Brechas de seguridad", "Comprueba si tus correos o contraseñas aparecen en filtraciones conocidas")
        data = self.vault.data["brechas"]

        info = tk.Frame(self.main, bg=PANEL2, highlightthickness=1, highlightbackground=LINE)
        info.pack(fill="x", padx=30, pady=(0, 10))
        for text in ("🔒  Contraseñas: se comprueban en Have I Been Pwned con k-anonimato; solo se envían 5 caracteres "
                     "de su hash SHA-1, nunca la contraseña.",
                     f"✉  Correos: se envían a XposedOrNot (servicio gratuito: máx. {MAIL_PER_RUN} por ejecución y 100 al día); "
                     "los que queden pendientes se comprueban la siguiente vez."):
            tk.Label(info, text=text, bg=PANEL2, fg=MUTED, font=("Segoe UI Emoji", 9), wraplength=700,
                     justify="left", anchor="w").pack(fill="x", padx=14, pady=4)

        ctl = tk.Frame(self.main, bg=PANEL)
        ctl.pack(fill="x", padx=30, pady=(0, 8))
        run = button(ctl, "Comprobar ahora", self.toggle_scan)
        run.pack(side="left")
        prog = tk.Frame(ctl, bg=PANEL)
        prog.pack(side="left", padx=16)
        plabel = tk.Label(prog, text="", bg=PANEL, fg=MUTED, font=("Segoe UI", 10), anchor="w")
        plabel.pack(anchor="w")
        pbar = tk.Canvas(prog, width=260, height=6, bg=PANEL, highlightthickness=0)
        pbar.pack(anchor="w", pady=(3, 0))

        # interruptor: comprobación automática al entrar (cada 7 días)
        auto = tk.Frame(ctl, bg=PANEL)
        auto.pack(side="right")
        sw = tk.Canvas(auto, width=44, height=24, bg=PANEL, highlightthickness=0, cursor="hand2")
        tk.Label(auto, text="Comprobar al entrar (cada 7 días)", bg=PANEL, fg=TEXT,
                 font=("Segoe UI", 10)).pack(side="left", padx=(0, 10))
        sw.pack(side="left")

        def draw_switch():
            on = self.cfg["breach_auto"]
            sw.delete("all")
            col = ACCENT if on else LINE
            sw.create_oval(0, 0, 24, 24, fill=col, outline=col)
            sw.create_oval(20, 0, 44, 24, fill=col, outline=col)
            sw.create_rectangle(12, 0, 32, 24, fill=col, outline=col)
            x = 22 if on else 2
            sw.create_oval(x, 2, x + 20, 22, fill="white", outline="white")

        def flip_auto(_=None):
            if not self.cfg["breach_auto"] and not self.ask_breach_consent():
                return
            self.cfg["breach_auto"] = not self.cfg["breach_auto"]
            save_cfg(self.cfg)
            draw_switch()

        sw.bind("<Button-1>", flip_auto)
        draw_switch()

        findings = data.get("findings", [])
        n_pw = sum(1 for f in findings if f["type"] == "pw")
        n_mail = len(findings) - n_pw
        last = data.get("last")
        if not last:
            summary, color = "Aún no se ha comprobado nada.", MUTED
        elif findings:
            summary, color = (f"⚠ {len(findings)} hallazgos: {n_pw} contraseñas y {n_mail} correos expuestos"
                              f"   ·   última comprobación {format_date(last)}"), DANGER
        else:
            summary, color = f"✅ No se ha encontrado nada   ·   última comprobación {format_date(last)}", OK
        if data.get("pending"):
            summary += f"   ·   {data['pending']} correos pendientes"
        tk.Label(self.main, text=summary, bg=PANEL, fg=color, font=("Segoe UI Emoji", 11, "bold"),
                 anchor="w").pack(fill="x", padx=30, pady=(4, 6))

        # tabla de resultados
        st = ttk.Style(self)
        st.theme_use("clam")
        st.configure("G.Treeview", background=PANEL2, fieldbackground=PANEL2, foreground=TEXT, rowheight=30,
                     borderwidth=0, font=("Segoe UI Emoji", 10))
        st.configure("G.Treeview.Heading", background=PANEL, foreground=MUTED, font=("Segoe UI", 9, "bold"),
                     borderwidth=0, relief="flat")
        st.map("G.Treeview", background=[("selected", ACCENT)], foreground=[("selected", "white")])
        st.map("G.Treeview.Heading", background=[("active", PANEL)])
        st.configure("Vertical.TScrollbar", background=LINE, troughcolor=PANEL, arrowcolor=MUTED, borderwidth=0)
        box = tk.Frame(self.main, bg=PANEL)
        box.pack(fill="both", expand=True, padx=(30, 12), pady=(0, 8))
        tree = ttk.Treeview(box, style="G.Treeview", columns=("tipo", "donde", "elem", "detalle"),
                            show="headings", selectmode="browse")
        for col, text, w, stretch in (("tipo", "TIPO", 120, False), ("donde", "SECCIÓN", 80, False),
                                      ("elem", "ELEMENTO", 250, False), ("detalle", "DETALLE", 400, True)):
            tree.heading(col, text=text, anchor="w")
            tree.column(col, width=w, stretch=stretch, anchor="w")
        tree.tag_configure("pw", foreground=DANGER)
        tree.tag_configure("mail", foreground=WARN)
        vsb = ttk.Scrollbar(box, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        where = {}
        for f in findings:
            iid = tree.insert("", "end", tags=(f["type"],), values=(
                "🔑 Contraseña" if f["type"] == "pw" else "✉ Correo", SECTIONS[f["sec"]]["title"],
                short(f["user"], 38), f["detail"]))
            where[iid] = (f["sec"], f["user"])
        if findings:
            tk.Label(self.main, text="Doble clic en un resultado para ir a esa entrada.", bg=PANEL, fg=MUTED,
                     font=("Segoe UI", 9), anchor="w").pack(fill="x", padx=30, pady=(0, 6))

        def open_entry(_):
            sel = tree.selection()
            if sel:
                sec, text = where[sel[0]]
                self.current, self.query, self.only_dups = sec, text, False
                self.show_list()

        tree.bind("<Double-1>", open_entry)

        def sync():
            if not run.winfo_exists():
                return
            s = self.scan
            pbar.delete("all")
            if not s:
                run.config(text="Comprobar ahora")
                plabel.config(text="")
                return
            p = s["progress"]
            run.config(text="Cancelar")
            names = {"pw": "Contraseñas", "mail": "Correos"}
            plabel.config(text=("Cancelando…" if s["cancel"].is_set() else
                                f"{names[p['phase']]}: {p['done']} / {p['total']}" if p["total"] else "Iniciando…"))
            pbar.create_rectangle(0, 0, 260, 6, fill=LINE, outline="")
            if p["total"]:
                pbar.create_rectangle(0, 0, 260 * p["done"] / p["total"], 6, fill=ACCENT, outline="")

        self.scan_ui = sync
        sync()

    def ask_breach_consent(self):
        if self.cfg["breach_consent"]:
            return True
        if messagebox.askyesno(
                "Comprobar brechas",
                "Para comprobarlo, la app se conectará a internet:\n\n"
                "• Contraseñas → Have I Been Pwned. Solo se envían los 5 primeros caracteres del hash SHA-1 "
                "de cada una (k-anonimato); la contraseña nunca sale de tu PC.\n"
                "• Correos → XposedOrNot. Aquí sí se envía cada dirección de correo al servicio.\n\n"
                "¿Quieres continuar?", icon="question", parent=self):
            self.cfg["breach_consent"] = True
            save_cfg(self.cfg)
            return True
        return False

    def toggle_scan(self):
        if self.scan:
            self.scan["cancel"].set()
            self.scan_ui()
        else:
            self.start_scan()

    def start_scan(self, auto=False):
        if self.scan or not self.unlocked:
            return
        if not self.cfg["breach_consent"] and (auto or not self.ask_breach_consent()):
            return
        entries = [(sec, e) for sec in SECTIONS for e in self.vault.data[sec]]
        passwords = sorted({e["pass"] for _, e in entries if e["pass"]})
        emails = {}  # correo -> [(sección, elemento)] donde aparece (también dentro de alias)
        for sec, e in entries:
            for m in EMAIL_RE.findall(e["user"] + " " + e.get("alias", "")):
                emails.setdefault(m.lower(), []).append((sec, e["user"]))
        if not passwords and not emails:
            if not auto:
                messagebox.showinfo("Brechas", "No hay nada que comprobar todavía.", parent=self)
            return
        cache = self.vault.data["brechas"].setdefault("emails", {})

        def fresh(em):
            try:
                return datetime.now() - datetime.fromisoformat(cache[em]["d"]) < timedelta(days=MAIL_TTL_DAYS)
            except (KeyError, TypeError, ValueError):
                return False

        stale = sorted((em for em in emails if not fresh(em)),
                       key=lambda em: (not any(s == "correos" for s, _ in emails[em]), em))
        todo = stale[:MAIL_PER_RUN]
        state = {"progress": {"phase": "pw", "done": 0, "total": 0}, "cancel": threading.Event(), "res": None,
                 "done": False, "entries": entries, "emails": emails, "todo": todo,
                 "pending": len(stale) - len(todo), "n_pw": len(passwords)}

        def progress(phase, done, total):
            state["progress"] = {"phase": phase, "done": done, "total": total}

        def worker():
            try:
                state["res"] = scan(passwords, todo, progress, state["cancel"])
            except Exception as ex:
                state["res"] = {"error": str(ex)}
            state["done"] = True

        threading.Thread(target=worker, daemon=True).start()
        self.scan = state
        self.after(150, self.poll_scan, state)
        if self.current == "breach":
            self.scan_ui()

    def poll_scan(self, state):
        if self.scan is not state:  # bloqueada la app u otra comprobación
            return
        if self.current == "breach":
            try:
                self.scan_ui()
            except tk.TclError:
                pass
        if state["done"]:
            self.finish_scan(state)
        else:
            self.after(150, self.poll_scan, state)

    def finish_scan(self, state):
        self.scan = None
        res = state["res"]
        if self.current == "breach":
            self.show_breach()
        if res.get("error"):
            messagebox.showerror("Brechas", f"La comprobación falló: {res['error']}", parent=self)
            return
        if res["cancelled"]:
            self.toast("Comprobación cancelada")
            return
        if state["n_pw"] and res["pw_errors"] >= state["n_pw"] and not res["mail"]:
            messagebox.showerror("Brechas", "No se pudo conectar con los servicios. Revisa tu conexión a internet "
                                 "e inténtalo de nuevo.", parent=self)
            return
        data = self.vault.data["brechas"]
        cache = data.setdefault("emails", {})
        for em, names in res["mail"].items():
            cache[em] = {"d": now_iso(), "b": names}
        findings = []
        for sec, e in state["entries"]:
            n = res["pw"].get(e["pass"])
            if n:
                # "h" (SHA-1 de una contraseña ya pública en filtraciones, guardado cifrado) permite marcar
                # en las listas cualquier entrada que use esa contraseña, aunque se edite o se añada después
                findings.append({"type": "pw", "sec": sec, "user": e["user"], "n": n, "h": pw_hash(e["pass"]),
                                 "detail": f"Contraseña vista {n:,} veces en filtraciones. Cámbiala.".replace(",", ".")})
        for em, places in state["emails"].items():
            names = (cache.get(em) or {}).get("b") or []
            if names:
                extra = f"  ·  en {len(places)} entradas" if len(places) > 1 else ""
                findings.append({"type": "mail", "sec": places[0][0], "user": em,
                                 "detail": f"{len(names)} brechas: " + ", ".join(names[:8])
                                           + (" …" if len(names) > 8 else "") + extra})
        findings.sort(key=lambda f: f["type"] != "pw")
        data["findings"] = findings
        data["last"] = now_iso()
        data["pending"] = state["pending"] + len(state["todo"]) - len(res["mail"])
        self.vault.save()

        n_pw = sum(1 for f in findings if f["type"] == "pw")
        n_mail = len(findings) - n_pw
        lines = []
        if findings:
            lines.append(f"Se han encontrado {len(findings)} problemas:")
            lines.append(f"• {n_pw} contraseñas aparecen en filtraciones conocidas")
            lines.append(f"• {n_mail} correos aparecen en brechas de seguridad")
            lines.append("\nCambia esas contraseñas cuanto antes. Los detalles están en la sección Brechas.")
        else:
            lines.append("✅ Ninguna de las contraseñas ni de los correos comprobados aparece en brechas conocidas.")
        if res["pw_errors"]:
            lines.append(f"\n{res['pw_errors']} contraseñas no se pudieron comprobar (error de red).")
        if res["rate_limited"]:
            lines.append("\nEl servicio gratuito de correos alcanzó su límite. Vuelve a probar dentro de una hora.")
        if data["pending"]:
            lines.append(f"\nQuedan {data['pending']} correos por comprobar: pulsa de nuevo «Comprobar ahora» más tarde.")
        (messagebox.showwarning if findings else messagebox.showinfo)("Brechas de seguridad", "\n".join(lines),
                                                                       parent=self)
        if self.current == "breach":
            self.show_breach()
        else:
            self.refresh_nav()

    def after_login(self):
        """Avisa de intentos fallidos desde la última visita y, si está activada, lanza la comprobación de brechas."""
        n = denied_unseen(self.cfg)
        if n:
            self.after(900, lambda: self.toast(f"⚠ {n} intento{'s' if n != 1 else ''} de acceso fallido{'s' if n != 1 else ''}: "
                                               "mira «Accesos denegados»"))
        if not (self.cfg["breach_consent"] and self.cfg["breach_auto"]):
            return
        last = self.vault.data["brechas"].get("last")
        try:
            due = not last or datetime.now() - datetime.fromisoformat(last) > timedelta(days=AUTO_DAYS)
        except (TypeError, ValueError):
            due = True
        if due:
            self.after(2000, lambda: self.start_scan(auto=True))

    # --- Extensión del navegador (Chrome, Brave, Edge) ---
    def bridge_start(self):
        self.bridge_stop()
        self.bridge_error = ""
        if not self.cfg["bridge_enabled"] or not self.cfg["bridge_token"]:
            return
        b = Bridge(self.cfg["bridge_port"], self.cfg["bridge_token"], self.bridge_items.append, lambda: self.unlocked)
        try:
            b.start()
            self.bridge = b
        except OSError as ex:
            self.bridge_error = str(ex)

    def bridge_stop(self):
        if self.bridge:
            self.bridge.stop()
            self.bridge = None

    def bridge_install(self):
        """Copia la extensión a la carpeta de datos con la clave y el puerto de esta instalación."""
        if not self.cfg["bridge_token"]:
            self.cfg["bridge_token"] = secrets.token_hex(24)
        self.cfg["bridge_enabled"] = True
        save_cfg(self.cfg)
        dest = os.path.join(APP_DIR, "extension")
        os.makedirs(dest, exist_ok=True)
        src = resource("extension")
        for name in ("background.js", "content.js"):
            shutil.copy2(os.path.join(src, name), os.path.join(dest, name))
        with open(os.path.join(src, "manifest.json"), encoding="utf-8") as f:
            manifest = f.read().replace("__PORT__", str(self.cfg["bridge_port"]))
        with open(os.path.join(dest, "manifest.json"), "w", encoding="utf-8") as f:
            f.write(manifest)
        with open(os.path.join(dest, "config.js"), "w", encoding="utf-8") as f:
            f.write(f'var GP = {{ port: {self.cfg["bridge_port"]}, token: "{self.cfg["bridge_token"]}" }};\n')
        self.bridge_start()
        return dest

    def bridge_tick(self):
        try:
            now = time.time()
            while self.bridge_items and now - self.bridge_items[0]["t"] > BRIDGE_TTL:
                self.bridge_items.popleft()  # caducado
            if self.unlocked and not self.bridge_busy and self.bridge_items:
                item = self.bridge_items.popleft()
                self.bridge_busy = True
                try:
                    self.bridge_handle(item)
                finally:
                    self.bridge_busy = False
        finally:
            self.after(400, self.bridge_tick)

    def bridge_confirm(self, title, text, ok_label):
        dlg = tk.Toplevel(self, bg=PANEL, padx=28, pady=22)
        dlg.title(title)
        dlg.resizable(False, False)
        dlg.wm_attributes("-topmost", True)
        result = {"ok": False}
        tk.Label(dlg, text="🔐  " + title, bg=PANEL, fg=TEXT, font=("Segoe UI Emoji", 14, "bold")).pack(anchor="w")
        tk.Label(dlg, text=text, bg=PANEL, fg=MUTED, font=("Segoe UI", 10), wraplength=380,
                 justify="left").pack(anchor="w", pady=(8, 16))

        def ok(_=None):
            result["ok"] = True
            dlg.destroy()

        bar = tk.Frame(dlg, bg=PANEL)
        bar.pack(anchor="w")
        button(bar, ok_label, ok).pack(side="left")
        button(bar, "Ahora no", dlg.destroy, primary=False).pack(side="left", padx=10)
        dlg.bind("<Escape>", lambda e: dlg.destroy())
        dlg.update_idletasks()
        dlg.geometry(f"+{(dlg.winfo_screenwidth() - dlg.winfo_reqwidth()) // 2}"
                     f"+{(dlg.winfo_screenheight() - dlg.winfo_reqheight()) // 3}")
        dlg.focus_force()
        self.wait_window(dlg)
        return result["ok"]

    def bridge_handle(self, item):
        """Guarda o actualiza en Webs la cuenta detectada en el navegador."""
        host, user, pw = host_of(item["url"]), item["username"], item["password"]
        webs = self.vault.data["webs"]
        idx = find_web(webs, host, user)
        ask = self.cfg["bridge_confirm"]
        stamp = now_iso()
        if idx is None:
            if ask and not self.bridge_confirm(
                    "Guardar cuenta", f"Se ha detectado un registro o inicio de sesión en {host}.\n\n"
                    f"Usuario: {user}\nContraseña: {'•' * min(len(pw), 12)}\n\n¿Guardarla en Webs?", "Guardar"):
                return
            webs.append(self.vault.new_entry({"user": origin_of(item["url"]), "pass": pw, "alias": user, "notes": "",
                                              "created": stamp, "changed": stamp}))
            msg = f"Guardada: {user} en {host}"
        elif webs[idx]["pass"] != pw:
            if ask and not self.bridge_confirm(
                    "Actualizar contraseña", f"Ya tienes guardado {user} en {host}, pero con otra contraseña.\n\n"
                    "¿Quieres actualizarla?\n(Si acabas de equivocarte al iniciar sesión, pulsa «Ahora no».)",
                    "Actualizar"):
                return
            webs[idx].update(**{"pass": pw, "changed": stamp, "modified": stamp, "rev": now_rev()})
            msg = f"Actualizada: {user} en {host}"
        else:
            return  # ya está guardada y es la misma contraseña
        self.vault.save()
        if self.in_form or self.current not in SECTIONS:
            self.refresh_nav()
        else:
            self.show_list()
        self.toast(msg)

    # --- Actualizaciones ---
    def update_start(self, manual=False):
        if self.update_busy or not (manual or self.cfg["update_check"]):
            return
        self.update_busy = True

        def work():
            try:
                self.update_q.put((manual, "ok", check_update()))
            except Exception as e:
                self.update_q.put((manual, "err", e))

        threading.Thread(target=work, daemon=True).start()
        self.after(300, self.update_poll)

    def update_poll(self):
        try:
            manual, kind, res = self.update_q.get_nowait()
        except queue.Empty:
            self.after(300, self.update_poll)
            return
        self.update_busy = False
        if kind == "err":
            if manual:
                messagebox.showwarning("Actualizaciones", f"No se pudo comprobar si hay una versión nueva.\n\n{_why(res)}",
                                       parent=self)
        elif res is None:
            if manual:
                messagebox.showinfo("Actualizaciones", f"Ya tienes la última versión ({APP_VERSION}).", parent=self)
        elif manual or res["version"] != self.cfg["update_skip"]:
            self.show_update(res)

    def show_update(self, m):
        dlg = tk.Toplevel(self, bg=PANEL, padx=30, pady=24)
        dlg.title("Actualización disponible")
        dlg.resizable(False, False)
        dlg.transient(self)
        self.update_idletasks()
        dlg.geometry(f"+{self.winfo_rootx() + 160}+{self.winfo_rooty() + 60}")
        tk.Label(dlg, text=f"⬆  Versión {m['version']} disponible", bg=PANEL, fg=TEXT,
                 font=("Segoe UI Emoji", 14, "bold")).pack(anchor="w")
        tk.Label(dlg, text=f"Tienes la {APP_VERSION}" + (f"  ·  publicada el {m['date']}" if m.get("date") else ""),
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(2, 10))
        notes = [str(x) for x in m.get("notes", [])][:12] if isinstance(m.get("notes"), list) else []
        if m.get("title"):
            tk.Label(dlg, text=str(m["title"]), bg=PANEL, fg=TEXT, font=("Segoe UI", 11, "bold"), anchor="w").pack(anchor="w")
        for n in notes:
            tk.Label(dlg, text="•  " + n, bg=PANEL, fg=MUTED, font=("Segoe UI", 10), wraplength=480,
                     justify="left", anchor="w").pack(anchor="w", pady=2)
        status = tk.Label(dlg, text="", bg=PANEL, fg=MUTED, font=("Segoe UI", 10), anchor="w")
        status.pack(anchor="w", pady=(10, 0))
        bar = tk.Frame(dlg, bg=PANEL)
        bar.pack(anchor="w", pady=(12, 0))
        state = {"done": None, "got": 0, "cancel": False}
        exe = sys.executable
        frozen = bool(getattr(sys, "frozen", False))
        nuevo = os.path.join(os.path.dirname(exe), "GestorContraseñas.nuevo")
        anterior = os.path.join(os.path.dirname(exe), "GestorContraseñas.anterior.exe")

        def close():
            state["cancel"] = True
            dlg.destroy()

        def skip():
            self.cfg["update_skip"] = m["version"]
            save_cfg(self.cfg)
            close()

        def poll():
            if not dlg.winfo_exists():
                return
            if state["done"] is None:
                status.config(text=f"Descargando… {state['got'] * 100 // m['size']} %", fg=MUTED)
                dlg.after(150, poll)
            elif state["done"] is True:
                status.config(text="Descarga verificada. Reiniciando para instalar…", fg=OK)
                dlg.update()
                try:
                    launch_swap(nuevo, exe, anterior)
                except Exception as e:
                    status.config(text=f"No se pudo iniciar la instalación: {_why(e)}", fg=DANGER)
                    return
                self.destroy()
                os._exit(0)
            else:
                status.config(text=f"No se pudo actualizar: {_why(state['done'])}", fg=DANGER)
                go.config(state="normal")

        def start():
            if not frozen:
                messagebox.showinfo("Actualizaciones", "Esta copia se ejecuta desde el código fuente: la actualización "
                                    "automática solo funciona con el ejecutable.", parent=dlg)
                return
            go.config(state="disabled")

            def work():
                try:
                    download_update(m, nuevo, progress=lambda n, t: state.update(got=n), cancel=lambda: state["cancel"])
                    state["done"] = True
                except Exception as e:
                    state["done"] = e

            threading.Thread(target=work, daemon=True).start()
            poll()

        go = button(bar, "Actualizar ahora", start)
        go.pack(side="left")
        button(bar, "Más tarde", close, primary=False).pack(side="left", padx=10)
        button(bar, "Omitir esta versión", skip, primary=False).pack(side="left")
        dlg.protocol("WM_DELETE_WINDOW", close)

    def show_bridge_settings(self):
        dlg = tk.Toplevel(self, bg=PANEL, padx=30, pady=24)
        dlg.title("Extensión del navegador")
        dlg.resizable(False, False)
        dlg.transient(self)
        self.update_idletasks()
        dlg.geometry(f"+{self.winfo_rootx() + 160}+{self.winfo_rooty() + 60}")
        tk.Label(dlg, text="🔌  Extensión del navegador", bg=PANEL, fg=TEXT,
                 font=("Segoe UI Emoji", 14, "bold")).pack(anchor="w")
        tk.Label(dlg, text="Al registrarte o iniciar sesión en Chrome, Brave o Edge, el Gestor comprueba si ya tienes "
                           "ese correo o usuario guardado para esa web: si existe, te propone actualizar la "
                           "contraseña; si no, te propone guardar la web, el usuario y la contraseña.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 10), wraplength=470, justify="left").pack(anchor="w", pady=(6, 12))
        status = tk.Label(dlg, text="", bg=PANEL, font=("Segoe UI Emoji", 10, "bold"), anchor="w")
        status.pack(anchor="w")

        def refresh():
            if self.bridge and self.bridge.running:
                status.config(text=f"● Activo: escuchando solo en este PC (127.0.0.1:{self.cfg['bridge_port']})", fg=OK)
            elif self.cfg["bridge_enabled"]:
                status.config(text=f"⚠ No se pudo abrir el puerto {self.cfg['bridge_port']} ({self.bridge_error})", fg=DANGER)
            else:
                status.config(text="○ Desactivado", fg=MUTED)

        def install():
            dest = self.bridge_install()
            refresh()
            os.startfile(dest)

        def disable():
            self.cfg["bridge_enabled"] = False
            save_cfg(self.cfg)
            self.bridge_stop()
            refresh()

        bar = tk.Frame(dlg, bg=PANEL)
        bar.pack(anchor="w", pady=(10, 12))
        button(bar, "Activar e instalar extensión", install).pack(side="left")
        button(bar, "Desactivar", disable, primary=False).pack(side="left", padx=10)

        row = tk.Frame(dlg, bg=PANEL)
        row.pack(anchor="w", pady=(0, 12))
        sw = tk.Canvas(row, width=44, height=24, bg=PANEL, highlightthickness=0, cursor="hand2")
        sw.pack(side="left")
        tk.Label(row, text="Pedir confirmación antes de guardar o actualizar (recomendado)", bg=PANEL, fg=TEXT,
                 font=("Segoe UI", 10)).pack(side="left", padx=10)

        def draw_switch():
            on = self.cfg["bridge_confirm"]
            sw.delete("all")
            col = ACCENT if on else LINE
            sw.create_oval(0, 0, 24, 24, fill=col, outline=col)
            sw.create_oval(20, 0, 44, 24, fill=col, outline=col)
            sw.create_rectangle(12, 0, 32, 24, fill=col, outline=col)
            x = 22 if on else 2
            sw.create_oval(x, 2, x + 20, 22, fill="white", outline="white")

        def flip(_=None):
            self.cfg["bridge_confirm"] = not self.cfg["bridge_confirm"]
            save_cfg(self.cfg)
            draw_switch()

        sw.bind("<Button-1>", flip)
        tk.Label(dlg, text="Cómo instalarla (una sola vez):\n"
                           "1. Pulsa «Activar e instalar extensión»: se abre una carpeta.\n"
                           "2. En el navegador abre chrome://extensions (brave://extensions o edge://extensions).\n"
                           "3. Activa el «Modo de desarrollador».\n"
                           "4. Pulsa «Cargar descomprimida» y elige esa carpeta.\n\n"
                           "El Gestor debe estar abierto. Si está bloqueado, el aviso espera hasta 10 minutos y se "
                           "muestra al desbloquearlo. Sin confirmación, cualquier programa de este PC con acceso a "
                           "la clave de conexión podría añadir o cambiar contraseñas: déjala activada.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 9), wraplength=470, justify="left").pack(anchor="w")
        button(dlg, "Cerrar", dlg.destroy, primary=False).pack(anchor="w", pady=(14, 0))
        draw_switch()
        refresh()

    # --- Comprobación de webs ---
    def start_webcheck(self, targets, ui):
        """Comprueba en paralelo cada web (en hilos, sin bloquear la interfaz). `ui` repinta el botón."""
        if self.webcheck or not targets:
            return
        st = {"done": 0, "total": len(targets), "cancel": threading.Event(), "results": {}, "finished": False}
        self.webcheck, self.webcheck_ui = st, ui

        def work(t):
            if st["cancel"].is_set():
                return t[0], None
            return t[0], check_site(t[1])

        def runner():
            with ThreadPoolExecutor(12) as ex:
                for f in as_completed([ex.submit(work, t) for t in targets]):
                    id_, res = f.result()
                    if res is not None:
                        st["results"][id_] = res
                    st["done"] += 1
            st["finished"] = True

        threading.Thread(target=runner, daemon=True).start()
        ui()
        self.after(200, self.webcheck_poll)

    def webcheck_poll(self):
        st = self.webcheck
        if st is None:
            return
        if st["finished"]:
            self.finish_webcheck(st)
            return
        try:
            self.webcheck_ui()
        except tk.TclError:
            pass
        self.after(200, self.webcheck_poll)

    def finish_webcheck(self, st):
        self.webcheck = None
        if not self.unlocked:
            return
        wc = self.vault.data["webcheck"]
        alive = {e["id"] for e in self.vault.data["webs"]}
        for k in [k for k in wc if k not in alive]:
            del wc[k]  # webs que ya no existen
        stamp, down, checked, skipped = now_iso(), 0, 0, 0
        for id_, (ok, why) in st["results"].items():
            if ok is None:
                wc.pop(id_, None)  # no es una dirección web (p. ej. solo el nombre del sitio)
                skipped += 1
                continue
            wc[id_] = {"ok": ok, "why": why, "t": stamp}
            checked += 1
            down += not ok
        self.vault.save()
        try:
            self.webcheck_ui()
        except tk.TclError:
            pass
        head = "Comprobación cancelada" if st["cancel"].is_set() else "Comprobación terminada"
        extra = f" · {skipped} omitidas (no son direcciones web)" if skipped else ""
        self.toast(f"{head}: {down} no disponible{'s' if down != 1 else ''} de {checked}{extra}")

    # --- Sincronización con el móvil ---
    def sync_start(self):
        self.sync_stop()
        self.sync_error = ""
        if not self.cfg["sync_enabled"]:
            return
        try:
            cert, key, self.sync_fp = ensure_cert()
            srv = SyncServer(self.cfg["sync_port"], cert, key, self.sync_run_main, self.sync_pair, self.sync_auth,
                             self.sync_apply, lambda: self.unlocked, self.sync_denied)
            srv.start()
            self.sync_srv = srv
        except (OSError, ssl.SSLError) as ex:
            self.sync_error = str(ex)

    def sync_stop(self):
        if self.sync_srv:
            self.sync_srv.stop()
            self.sync_srv = None

    def sync_run_main(self, fn):
        """Llamado desde los hilos del servidor: ejecuta `fn` en el hilo de la interfaz y espera el resultado."""
        job = {"fn": fn, "ev": threading.Event(), "res": (500, None)}
        self.sync_jobs.put(job)
        job["ev"].wait(25)
        return job["res"]

    def sync_tick(self):
        while True:
            try:
                job = self.sync_jobs.get_nowait()
            except queue.Empty:
                break
            try:
                job["res"] = job["fn"]()
            except Exception:
                job["res"] = (500, None)
            job["ev"].set()
        self.after(150, self.sync_tick)

    def sync_pair(self, code, name):
        """(hilo del servidor) Canjea el código de vinculación por las credenciales del dispositivo."""
        return self.sync_run_main(lambda: (200, self._pair_main(code, name)))[1]

    def _pair_main(self, code, name):
        p = self.pair_state
        if not p or time.time() > p["exp"] or p["fails"] >= 5:
            return None
        if not hmac.compare_digest(code.encode(), p["code"].encode()):
            p["fails"] += 1
            return None
        self.pair_state = None  # el código vale una sola vez
        secret = secrets.token_urlsafe(32)
        dev = {"id": uuid.uuid4().hex[:8], "name": name or "Móvil", "created": now_iso(), "last": "",
               "hash": hashlib.sha256(secret.encode()).hexdigest()}
        self.cfg["sync_devices"].append(dev)
        save_cfg(self.cfg)
        p["paired"] = dev["name"]
        self.last_paired = dev["name"]
        return {"device_id": dev["id"], "secret": secret}

    def sync_auth(self, token):
        """(hilo del servidor) 'id.secreto' -> dispositivo vinculado, o None."""
        dev_id, _, secret = token.partition(".")
        digest = hashlib.sha256(secret.encode()).hexdigest()
        for d in list(self.cfg["sync_devices"]):
            if d["id"] == dev_id and hmac.compare_digest(d["hash"], digest):
                return d
        return None

    def sync_apply(self, device, blob):
        """Fusiona los datos recibidos del móvil con los del PC y devuelve el resultado (hilo de la interfaz)."""
        if not self.unlocked:
            return 423, None
        snap = self.vault.sync_snapshot()
        changed = False
        merged = snap
        if blob is not None:
            try:
                remote = self.vault.unpack(blob)
                if not isinstance(remote, dict):
                    raise ValueError
            except (InvalidToken, ValueError, KeyError):
                return 409, None  # otra contraseña maestra o datos ajenos: hay que volver a vincular
            merged = merge_data(snap, remote)
            changed = json.dumps(merged, sort_keys=True) != json.dumps(snap, sort_keys=True)
            if changed:
                self.vault.apply_merged(merged)
            # intentos de acceso fallidos del móvil: solo los que se pueden descifrar con la clave de este almacén
            if isinstance(remote.get("denied"), list):
                priv = self.vault.data.get("denykey", "")
                new_denied = denied_merge([r for r in remote["denied"] if isinstance(r, dict) and
                                           can_unseal(priv, r.get("blob", ""))], merged["deleted"])
                if new_denied:
                    self.denied_arrived(new_denied, device["name"])
        for d in self.cfg["sync_devices"]:
            if d["id"] == device["id"]:
                d["last"] = now_iso()
        save_cfg(self.cfg)
        if changed:
            if self.in_form or self.current not in SECTIONS:
                self.refresh_nav()
            else:
                self.show_list()
            self.toast(f"Sincronizado con {device['name']}")
        # la clave del registro viaja con la respuesta (cifrada con la contraseña maestra) para que el móvil
        # use la misma y los dos dispositivos puedan leer los intentos del otro
        reply = {**merged, "denied": denied_synced(), "denykey": self.vault.data.get("denykey", "")}
        return 200, self.vault.pack(reply)

    def sync_denied(self, device, entries):
        """(hilo de la interfaz) Intentos fallidos enviados por el móvil, aunque el PC esté bloqueado."""
        new = denied_merge(entries, self.vault.data.get("deleted", {}) if self.unlocked else {})
        if new:
            self.denied_arrived(new, device["name"])
        return 200, {"stored": new}

    def denied_arrived(self, n, who):
        """Avisa de intentos fallidos llegados de otro dispositivo."""
        if not self.unlocked:
            return
        self.refresh_nav()
        if self.current == "denied":
            self.show_denied()
        self.toast(f"⚠ {n} intento{'s' if n != 1 else ''} de acceso fallido{'s' if n != 1 else ''} en {who}")

    def sync_new_pairing(self):
        """Genera un código de un solo uso (5 min) y el enlace que va en el QR."""
        code = secrets.token_hex(5).upper()
        self.pair_state = {"code": code, "exp": time.time() + PAIR_TTL, "fails": 0}
        payload = {"v": 1, "h": lan_ips()[:4], "p": self.cfg["sync_port"], "f": self.sync_fp, "c": code}
        raw = json.dumps(payload, separators=(",", ":")).encode()
        return "gestor://pair?d=" + base64.urlsafe_b64encode(raw).decode().rstrip("="), payload

    def show_sync_dialog(self):
        import qrcode
        from PIL import ImageTk
        dlg = tk.Toplevel(self, bg=PANEL, padx=28, pady=22)
        dlg.title("Sincronización con el móvil")
        dlg.resizable(False, False)
        dlg.transient(self)
        self.update_idletasks()
        dlg.geometry(f"+{self.winfo_rootx() + 130}+{self.winfo_rooty() + 20}")
        tk.Label(dlg, text="📱  Sincronización con el móvil", bg=PANEL, fg=TEXT,
                 font=("Segoe UI Emoji", 14, "bold")).pack(anchor="w")
        tk.Label(dlg, text="Vincula la app de Android con este PC para añadir y modificar contraseñas desde los dos "
                           "dispositivos. Los datos viajan cifrados por tu red local (misma Wi-Fi), sin pasar por "
                           "ningún servidor externo.", bg=PANEL, fg=MUTED, font=("Segoe UI", 10), wraplength=500,
                 justify="left").pack(anchor="w", pady=(6, 10))
        status = tk.Label(dlg, text="", bg=PANEL, font=("Segoe UI Emoji", 10, "bold"), anchor="w", justify="left",
                          wraplength=500)
        status.pack(anchor="w")
        bar = tk.Frame(dlg, bg=PANEL)
        bar.pack(anchor="w", pady=(10, 8))
        qr_box = tk.Frame(dlg, bg=PANEL)
        dev_box = tk.Frame(dlg, bg=PANEL)
        state = {"img": None, "label": None}

        def running():
            return bool(self.sync_srv and self.sync_srv.running)

        def fill_devices():
            for w in dev_box.winfo_children():
                w.destroy()
            devs = self.cfg["sync_devices"]
            tk.Label(dev_box, text="Móviles vinculados" if devs else "Aún no hay ningún móvil vinculado.", bg=PANEL,
                     fg=TEXT if devs else MUTED, font=("Segoe UI", 10, "bold" if devs else "normal")).pack(anchor="w")
            for d in list(devs):
                row = tk.Frame(dev_box, bg=PANEL2, highlightthickness=1, highlightbackground=LINE)
                row.pack(fill="x", pady=3)
                last = format_date(d["last"]) if d.get("last") else "nunca"
                tk.Label(row, text=f"📱 {d['name']}\nVinculado {format_date(d['created'])} · última sincronización: {last}",
                         bg=PANEL2, fg=TEXT, font=("Segoe UI Emoji", 9), justify="left").pack(side="left", padx=10, pady=6)
                unlink = tk.Label(row, text="Desvincular", bg=PANEL2, fg=DANGER, font=("Segoe UI", 9, "bold"),
                                  cursor="hand2", padx=10)
                unlink.pack(side="right")
                unlink.bind("<Button-1>", lambda e, i=d["id"]: remove_device(i))

        def remove_device(dev_id):
            if messagebox.askyesno("Desvincular", "¿Desvincular este móvil? Dejará de poder sincronizar con este PC "
                                   "(sus datos locales se conservan en el móvil).", parent=dlg):
                self.cfg["sync_devices"] = [d for d in self.cfg["sync_devices"] if d["id"] != dev_id]
                save_cfg(self.cfg)
                fill_devices()

        def refresh():
            if running():
                ips = ", ".join(lan_ips()) or "sin red"
                status.config(text=f"● Activo en la red local ({ips}), puerto {self.cfg['sync_port']}", fg=OK)
            elif self.cfg["sync_enabled"]:
                status.config(text=f"⚠ No se pudo abrir el puerto {self.cfg['sync_port']}: {self.sync_error}", fg=DANGER)
            else:
                status.config(text="○ Desactivada", fg=MUTED)
            for w in bar.winfo_children():
                w.destroy()
            if self.cfg["sync_enabled"]:
                button(bar, "Vincular un móvil", pair).pack(side="left")
                button(bar, "Desactivar", disable, primary=False).pack(side="left", padx=10)
            else:
                button(bar, "Activar sincronización", enable).pack(side="left")

        def enable():
            self.cfg["sync_enabled"] = True
            save_cfg(self.cfg)
            self.sync_start()
            refresh()
            if running():
                pair()

        def disable():
            self.cfg["sync_enabled"] = False
            save_cfg(self.cfg)
            self.pair_state = None
            self.sync_stop()
            qr_box.pack_forget()
            refresh()

        def pair():
            if not running():
                self.sync_start()
                refresh()
                if not running():
                    return
            link, _ = self.sync_new_pairing()
            for w in qr_box.winfo_children():
                w.destroy()
            img = qrcode.make(link, box_size=5, border=2).resize((250, 250))
            state["img"] = ImageTk.PhotoImage(img)
            tk.Label(qr_box, image=state["img"], bg="white").pack(anchor="w", pady=(4, 6))
            state["label"] = tk.Label(qr_box, text="", bg=PANEL, fg=MUTED, font=("Segoe UI", 10), justify="left",
                                      wraplength=500)
            state["label"].pack(anchor="w")
            row = tk.Frame(qr_box, bg=PANEL)
            row.pack(anchor="w", pady=6)

            def copy_link():
                self.clipboard_clear()
                self.clipboard_append(link)
                self.toast("Enlace copiado")

            button(row, "Copiar enlace de vinculación", copy_link, primary=False).pack(side="left")
            qr_box.pack(anchor="w", before=dev_box)

        def tick():
            if not dlg.winfo_exists():
                return
            p = self.pair_state
            if state["label"] is not None and state["label"].winfo_exists():
                if p:
                    left = max(0, int(p["exp"] - time.time()))
                    state["label"].config(text=f"En la app del móvil: Vincular → escanea este QR. "
                                               f"Caduca en {left // 60}:{left % 60:02d}.")
                    if left == 0:
                        self.pair_state = None
                else:
                    qr_box.pack_forget()
                    state["label"] = None
                    fill_devices()
            dlg.after(1000, tick)

        tk.Label(dlg, text="Si Windows pregunta por el cortafuegos, permite el acceso en redes privadas. "
                           "El PC debe estar encendido, con el Gestor abierto y desbloqueado, en la misma red que el móvil.",
                 bg=PANEL, fg=MUTED, font=("Segoe UI", 9), wraplength=500, justify="left").pack(anchor="w", pady=(0, 8))
        dev_box.pack(fill="x", pady=(4, 0))
        button(dlg, "Cerrar", dlg.destroy, primary=False).pack(anchor="w", pady=(14, 0))
        refresh()
        fill_devices()
        tick()

    # --- Administrador ---
    def ask_password(self, title, text, confirm=False):
        """Diálogo modal. Devuelve la contraseña escrita o None si se cancela."""
        dlg = tk.Toplevel(self, bg=PANEL, padx=30, pady=24)
        dlg.title(title)
        dlg.resizable(False, False)
        dlg.transient(self)
        self.update_idletasks()
        dlg.geometry(f"+{self.winfo_rootx() + 300}+{self.winfo_rooty() + 170}")
        result = {"pw": None}
        tk.Label(dlg, text=title, bg=PANEL, fg=TEXT, font=("Segoe UI", 14, "bold")).pack(anchor="w")
        tk.Label(dlg, text=text, bg=PANEL, fg=MUTED, font=("Segoe UI", 10), wraplength=320,
                 justify="left").pack(anchor="w", pady=(2, 12))
        e1 = entry(dlg, show="•")
        e1.pack(fill="x", ipady=7)
        e2 = None
        if confirm:
            tk.Label(dlg, text="Repítela", bg=PANEL, fg=MUTED, font=("Segoe UI", 10)).pack(anchor="w", pady=(10, 2))
            e2 = entry(dlg, show="•")
            e2.pack(fill="x", ipady=7)
        msg = tk.Label(dlg, text="", bg=PANEL, fg=DANGER, font=("Segoe UI", 10))
        msg.pack(pady=6)

        def ok(_=None):
            pw = e1.get()
            if confirm and len(pw) < 6:
                msg.config(text="Mínimo 6 caracteres.")
            elif confirm and pw != e2.get():
                msg.config(text="Las contraseñas no coinciden.")
            elif not pw:
                msg.config(text="Introduce la contraseña.")
            else:
                result["pw"] = pw
                dlg.destroy()

        bar = tk.Frame(dlg, bg=PANEL)
        bar.pack(anchor="w")
        button(bar, "Aceptar", ok).pack(side="left")
        button(bar, "Cancelar", dlg.destroy, primary=False).pack(side="left", padx=10)
        dlg.bind("<Return>", ok)
        dlg.bind("<Escape>", lambda e: dlg.destroy())
        e1.focus_set()
        dlg.grab_set()
        self.wait_window(dlg)
        return result["pw"]

    def open_admin(self):
        if self.current != "admin":
            pw = self.ask_password("Administrador", "Introduce de nuevo la contraseña maestra para continuar.")
            if pw is None:
                return
            if not self.vault.verify(pw):
                messagebox.showerror("Administrador", "Contraseña incorrecta.", parent=self)
                return
        self.current = "admin"
        self.show_admin()

    def show_admin(self, scroll=0.0):
        self.in_form = False
        self.clear(self.main)
        self.unbind("<Return>")
        self.unbind("<Escape>")
        self.refresh_nav()
        d = self.vault.data
        self.header("Administrador", "Gestión avanzada de tus datos")
        canvas, box = scroll_area(self.main)

        def card(title, desc, label, cmd, danger=False):
            c = tk.Frame(box, bg=PANEL2, highlightthickness=1, highlightbackground=LINE)
            c.pack(fill="x", pady=4, padx=(0, 16), ipady=4)
            c.columnconfigure(0, weight=1)
            tk.Label(c, text=title, bg=PANEL2, fg=TEXT, font=("Segoe UI Emoji", 12, "bold"),
                     anchor="w").grid(row=0, column=0, sticky="w", padx=16, pady=(6, 0))
            dl = tk.Label(c, text=desc, bg=PANEL2, fg=MUTED, font=("Segoe UI", 10), anchor="w")
            dl.grid(row=1, column=0, sticky="w", padx=16, pady=(0, 6))
            b = button(c, label, cmd, danger=danger)
            b.grid(row=0, column=1, rowspan=2, padx=16)
            return dl, b

        card("🗑  Eliminar todos los correos", f"Borra los {len(d['correos'])} correos guardados.",
             "Eliminar", lambda: self.wipe("correos"), True)
        card("🗑  Eliminar todas las webs", f"Borra las {len(d['webs'])} webs guardadas.",
             "Eliminar", lambda: self.wipe("webs"), True)

        def lock_text():
            m = self.cfg["lock_minutes"]
            return ("Nunca" if not m else f"{m} min"), ("Desactivado." if not m else f"Se bloquea tras {m} min sin actividad.")

        lock_label, lock_desc = lock_text()
        ld, lb = card("⏱  Bloqueo automático", lock_desc, lock_label + "  ▸", lambda: None)

        def cycle_lock():
            i = LOCK_OPTIONS.index(self.cfg["lock_minutes"]) if self.cfg["lock_minutes"] in LOCK_OPTIONS else 0
            self.cfg["lock_minutes"] = LOCK_OPTIONS[(i + 1) % len(LOCK_OPTIONS)]
            save_cfg(self.cfg)
            t, desc = lock_text()
            lb.config(text=t + "  ▸")
            ld.config(text=desc)

        lb.bind("<Button-1>", lambda e: cycle_lock())

        card("🔑  Cambiar contraseña maestra", "Vuelve a cifrar todos los datos con una clave nueva.",
             "Cambiar", self.change_master)
        card("💾  Copia de seguridad", "Guarda una copia cifrada de tus datos donde elijas.", "Exportar", self.backup)
        card("♻  Restaurar copia", f"Recupera una copia (se guardan automáticamente las últimas {MAX_BACKUPS} versiones).",
             "Restaurar", self.restore)
        card("🟣  Exportar para Proton Pass", "Crea un CSV listo para importar en Proton Pass (sin cifrar).",
             "Exportar", self.export_proton)
        card("🟣  Importar desde Proton Pass", "Lee su exportación en CSV, JSON o ZIP sin cifrar.",
             "Importar", lambda: self.import_csv(proton=True))
        card("📤  Exportar a CSV", "Texto plano, sin cifrar: úsalo solo para migrar a otro gestor.",
             "Exportar", self.export_csv)
        card("📥  Importar desde CSV", "Admite el CSV de Chrome/Edge, Proton Pass y el exportado por esta app.",
             "Importar", self.import_csv)
        card("🔌  Extensión del navegador", "Guarda o actualiza contraseñas al registrarte en Chrome, Brave o Edge.",
             "Configurar", self.show_bridge_settings)
        card("📱  Sincronizar con el móvil", "Vincula la app de Android para usar y editar tus contraseñas en los dos.",
             "Configurar", self.show_sync_dialog)
        card("⬆  Actualizaciones", f"Versión instalada: {APP_VERSION}. Comprueba si hay una versión nueva.",
             "Buscar ahora", lambda: self.update_start(manual=True))
        ud, ub = card("🔄  Buscar al abrir", "", "", lambda: None)

        def update_text():
            on = self.cfg["update_check"]
            return ("Sí" if on else "No") + "  ▸", ("Al abrir la aplicación se busca y se avisa de las versiones nuevas."
                                                   if on else "No se busca automáticamente (puedes hacerlo con «Buscar ahora»).")

        def toggle_update():
            self.cfg["update_check"] = not self.cfg["update_check"]
            save_cfg(self.cfg)
            t, desc = update_text()
            ub.config(text=t)
            ud.config(text=desc)

        ub.config(text=update_text()[0])
        ud.config(text=update_text()[1])
        ub.bind("<Button-1>", lambda e: toggle_update())
        card("📂  Abrir directorio de datos", "Abre en el Explorador la carpeta donde se guarda el archivo cifrado.",
             "Abrir", self.open_dir)
        self.update_idletasks()
        canvas.yview_moveto(scroll)

    def wipe(self, key):
        n = len(self.vault.data[key])
        if not n:
            messagebox.showinfo("Administrador", f"No hay {SECTIONS[key]['title'].lower()} guardados.", parent=self)
            return
        if messagebox.askyesno("Confirmar", f"¿Eliminar los {n} elementos de {SECTIONS[key]['title']}?\n"
                               "Esta acción no se puede deshacer.", icon="warning", parent=self):
            self.vault.remove(key, [e["id"] for e in self.vault.data[key]])
            self.vault.save()
            self.show_admin()
            self.toast("Eliminado")

    def change_master(self):
        pw = self.ask_password("Nueva contraseña maestra",
                               "Elige la nueva contraseña. Recuérdala: no se puede recuperar.", confirm=True)
        if pw is not None:
            self.vault.change_password(pw)
            self.toast("Contraseña cambiada")

    def backup(self):
        dest = filedialog.asksaveasfilename(parent=self, title="Guardar copia de seguridad",
                                            initialfile="boveda-copia.dat", defaultextension=".dat",
                                            filetypes=[("Archivo cifrado", "*.dat")])
        if dest:
            shutil.copy2(VAULT, dest)
            self.toast("Copia guardada")

    def restore(self):
        start = backup_dir() if os.path.isdir(backup_dir()) else APP_DIR
        path = filedialog.askopenfilename(parent=self, title="Elegir copia a restaurar", initialdir=start,
                                          filetypes=[("Archivo cifrado", "*.dat"), ("Todos", "*.*")])
        if not path:
            return
        pw = self.ask_password("Restaurar copia", "Introduce la contraseña maestra con la que se creó esa copia.")
        if pw is None:
            return
        candidate = Vault()
        try:
            ok = candidate.unlock(pw, path)
        except Exception:
            messagebox.showerror("Restaurar", "Ese archivo no es una copia válida.", parent=self)
            return
        if not ok:
            messagebox.showerror("Restaurar", "Contraseña incorrecta para esa copia.", parent=self)
            return
        n = sum(len(candidate.data[k]) for k in SECTIONS)
        if messagebox.askyesno("Restaurar", f"La copia contiene {n} elementos.\n"
                               "Sustituirá a los datos actuales (se guarda antes una copia de seguridad de ellos) "
                               "y su contraseña maestra pasará a ser la de la copia.\n\n¿Continuar?",
                               icon="warning", parent=self):
            self.vault = candidate
            self.vault.save()  # save() guarda antes la versión actual en la carpeta de copias
            self.show_admin()
            self.toast("Copia restaurada")

    CSV_FIELDS = ["section", "user", "password", "alias", "notes", "created", "changed", "modified"]

    def export_proton(self):
        if not messagebox.askyesno("Exportar para Proton Pass",
                                   "Se creará un CSV con el formato de Proton Pass. NO estará cifrado: cualquiera que "
                                   "lo abra verá todas tus contraseñas.\n\nImpórtalo en Proton Pass "
                                   "(Ajustes → Importar → Proton Pass → CSV) y bórralo después. ¿Continuar?",
                                   icon="warning", parent=self):
            return
        dest = filedialog.asksaveasfilename(parent=self, title="Exportar para Proton Pass",
                                            initialfile="proton-pass-import.csv", defaultextension=".csv",
                                            filetypes=[("CSV", "*.csv")])
        if not dest:
            return
        with open(dest, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(PROTON_FIELDS)
            for sec in SECTIONS:
                for e in self.vault.data[sec]:
                    w.writerow(proton_row(sec, e))
        self.toast("Exportado para Proton Pass")

    def export_csv(self):
        if not messagebox.askyesno("Exportar a CSV", "El archivo CSV NO estará cifrado: cualquiera que lo abra "
                                   "verá todas tus contraseñas.\n\nBórralo cuando termines de usarlo. ¿Continuar?",
                                   icon="warning", parent=self):
            return
        dest = filedialog.asksaveasfilename(parent=self, title="Exportar a CSV", initialfile="contraseñas.csv",
                                            defaultextension=".csv", filetypes=[("CSV", "*.csv")])
        if not dest:
            return
        with open(dest, "w", newline="", encoding="utf-8-sig") as f:
            w = csv.writer(f)
            w.writerow(self.CSV_FIELDS)
            for sec in SECTIONS:
                for e in self.vault.data[sec]:
                    w.writerow([sec, e["user"], e["pass"], e.get("alias", ""), e.get("notes", ""),
                                e.get("created", ""), e.get("changed", ""), e.get("modified", "")])
        self.toast("CSV exportado")

    def import_csv(self, proton=False):
        types = ([("Exportación de Proton Pass", "*.csv *.json *.zip"), ("Todos", "*.*")] if proton else
                 [("CSV, JSON o ZIP", "*.csv *.json *.zip"), ("Todos", "*.*")])
        path = filedialog.askopenfilename(parent=self, title="Importar desde Proton Pass" if proton else "Importar",
                                          filetypes=types)
        if not path:
            return
        try:
            entries, skipped, fmt = parse_import(path)
        except (OSError, UnicodeDecodeError, csv.Error, ValueError, zipfile.BadZipFile) as ex:
            messagebox.showerror("Importar", f"No se pudo importar: {ex}", parent=self)
            return
        added = 0
        for r in entries:
            sec, user, p, alias = r["sec"], r["user"], r["pass"], r["alias"]
            if not user or not p:
                skipped += 1
                continue
            if any(e["user"] == user and e["pass"] == p and e.get("alias", "") == alias
                   for e in self.vault.data[sec]):
                skipped += 1
                continue
            stamp = now_iso()
            self.vault.data[sec].append(self.vault.new_entry(
                {"user": user, "pass": p, "alias": alias, "notes": r["notes"],
                 "created": r["created"] or stamp, "changed": r["changed"] or stamp,
                 "modified": r.get("modified", "")}))
            added += 1
        if added:
            self.vault.save()
        self.show_admin()
        messagebox.showinfo("Importar", f"Formato detectado: {fmt}\nImportadas: {added}\n"
                            f"Omitidas (no son contraseñas de acceso, vacías o duplicadas): {skipped}", parent=self)

    def open_dir(self):
        os.makedirs(APP_DIR, exist_ok=True)
        os.startfile(APP_DIR)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--test-red":  # autocomprobación de red (para verificar el .exe)
        with open(sys.argv[2], "w", encoding="utf-8") as out:
            sha = hashlib.sha1(b"password").hexdigest().upper()
            out.write(f"password -> {hibp_range(sha[:5]).get(sha[5:])}\n")
        sys.exit(0)
    if len(sys.argv) == 3 and sys.argv[1] == "--test-ext":  # comprueba que la extensión viaja dentro del .exe
        with open(sys.argv[2], "w", encoding="utf-8") as out:
            out.write(",".join(sorted(os.listdir(resource("extension")))))
        sys.exit(0)
    App().mainloop()
