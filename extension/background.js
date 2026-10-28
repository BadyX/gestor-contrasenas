// Recibe las credenciales detectadas por content.js y se las envía al Gestor (solo por 127.0.0.1).
// config.js lo genera el Gestor al instalar la extensión: define GP = { port, token }.
importScripts("config.js");

function badge(text, color, title) {
  chrome.action.setBadgeText({ text });
  chrome.action.setBadgeBackgroundColor({ color });
  chrome.action.setTitle({ title });
  setTimeout(() => chrome.action.setBadgeText({ text: "" }), 6000);
}

async function send(url, username, password) {
  try {
    const r = await fetch(`http://127.0.0.1:${GP.port}/credential`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "X-GP-Token": GP.token },
      body: JSON.stringify({ url, username, password }),
    });
    const d = await r.json().catch(() => ({}));
    if (r.ok) {
      badge("✓", "#22b573", d.locked
        ? "El Gestor está bloqueado: se procesará al desbloquearlo"
        : "Enviado al Gestor de contraseñas");
    } else {
      badge("!", "#e0364f", "El Gestor rechazó la petición (¿se reinstaló la extensión con otra clave?)");
    }
  } catch (e) {
    badge("!", "#e0364f", "El Gestor de contraseñas no está abierto");
  }
}

chrome.runtime.onMessage.addListener((msg, sender) => {
  // la dirección la da el navegador (la del marco que envía, no lo que diga la página)
  if (msg && msg.type === "cred" && sender.tab && sender.url) {
    send(sender.url, String(msg.username || ""), String(msg.password || ""));
  }
});
