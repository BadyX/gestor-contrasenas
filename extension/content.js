// Detecta registros / inicios de sesión (formularios con contraseña) y avisa al Gestor.
// Cubre: <form> normales, formularios sin <form> (SPA), Shadow DOM, iframes y accesos en dos pasos
// (usuario en una pantalla y contraseña en la siguiente, de la misma web).
(() => {
  const REQUIRE_TRUSTED = true; // solo acciones reales del usuario, no las simuladas por scripts de la página
  const USER_HINT = /mail|correo|user|usuario|login|account|cuenta|identifier|nick|phone|tel/i;
  const MAIL_HINT = /mail|correo/i;
  // Botones que NO envían las credenciales: mostrar/ocultar contraseña, «olvidé mi contraseña», cerrar, cancelar...
  const NOT_SUBMIT = /show|mostrar|ver |hide|ocultar|eye|reveal|toggle|olvid|forgot|reset|cerrar|close|cancel|volver|back|atr[aá]s|editar|edit|dismiss|omitir|skip|invitado|guest/i;
  const STEP_KEY = "gp-step-user";
  let last = { key: "", t: 0 };

  const visible = (el) => !!(el.offsetWidth || el.offsetHeight || el.getClientRects().length);
  const attrs = (i) => [i.name, i.id, i.autocomplete, i.placeholder, i.getAttribute("aria-label")].join(" ");

  // <input> de `root` en orden de documento, entrando también en los Shadow DOM abiertos.
  function collect(root, out = []) {
    for (const el of root.children || []) {
      if (el.tagName === "INPUT") out.push(el);
      if (el.shadowRoot) collect(el.shadowRoot, out);
      collect(el, out);
    }
    return out;
  }

  const texty = (i) => ["text", "email", "tel"].includes(i.type) && i.value.trim() && visible(i);
  const pickUser = (pool) =>
    pool.find((i) => i.type === "email" || MAIL_HINT.test(attrs(i))) ||
    pool.find((i) => USER_HINT.test(attrs(i))) ||
    pool[pool.length - 1];

  // Usuario de un paso anterior (misma web, misma pestaña, menos de 10 min).
  function rememberedUser() {
    try {
      const d = JSON.parse(sessionStorage.getItem(STEP_KEY) || "null");
      return d && d.host === location.host && Date.now() - d.t < 600000 ? d.username : "";
    } catch (e) { return ""; }
  }

  // Busca en `root` una contraseña escrita y el usuario/correo que la acompaña.
  function findCredentials(root) {
    const inputs = collect(root);
    const pwds = inputs.filter((i) => i.type === "password" && i.value && visible(i));
    if (!pwds.length) return null;
    // en registros y cambios de contraseña, la "nueva" es la que cuenta (la 2.ª suele ser la confirmación)
    const pwd = pwds.find((i) => /new-password/.test(i.autocomplete)) || pwds[0];
    const before = inputs.slice(0, inputs.indexOf(pwd)).filter(texty);
    const pool = before.length ? before : inputs.filter(texty);
    const field = pickUser(pool);
    const username = field ? field.value.trim() : rememberedUser();
    return username ? { username, password: pwd.value } : null;
  }

  // Primer paso de un acceso en dos pasos: guarda el usuario/correo escrito para la pantalla siguiente.
  function rememberStep(root) {
    const inputs = collect(root);
    if (inputs.some((i) => i.type === "password" && visible(i))) return;
    const pool = inputs.filter((i) => texty(i) && (i.type === "email" || USER_HINT.test(attrs(i))));
    if (!pool.length) return;
    try {
      sessionStorage.setItem(STEP_KEY, JSON.stringify({ host: location.host, username: pool[0].value.trim(), t: Date.now() }));
    } catch (e) {}
  }

  function send(c) {
    const key = location.host + "|" + c.username + "|" + c.password;
    if (key === last.key && Date.now() - last.t < 4000) return; // submit + click + Enter = un solo aviso
    last = { key, t: Date.now() };
    try {
      chrome.runtime.sendMessage({ type: "cred", username: c.username, password: c.password });
    } catch (e) {}
  }

  const trusted = (e) => !REQUIRE_TRUSTED || e.isTrusted;
  const parentOf = (n) => n.parentElement || (n.getRootNode && n.getRootNode().host) || null; // sube también fuera del Shadow DOM

  // Sube por los ancestros hasta encontrar un bloque con contraseña rellena (formularios sin <form>).
  function fromNode(node, fn) {
    for (let n = 0; node && n < 10; n++, node = parentOf(node)) {
      const c = fn(node);
      if (c) return c;
    }
    return null;
  }

  const origin = (e) => (e.composedPath ? e.composedPath()[0] : e.target);

  document.addEventListener("submit", (e) => {
    if (!trusted(e)) return;
    const form = origin(e);
    const c = findCredentials(form);
    if (c) send(c); else rememberStep(form);
  }, true);

  document.addEventListener("click", (e) => {
    if (!trusted(e)) return;
    const start = origin(e);
    if (!start || !start.closest) return;
    const el = start.closest("button, input[type=submit], input[type=button], [role=button]");
    if (!el) return;
    const label = [el.textContent, el.value, el.getAttribute("aria-label"), el.title].join(" ").trim();
    // cualquier botón con texto (p. ej. «Hazte miembro», «Conectarse», «Únete»); los iconos sin texto, como el ojo, no
    const isSubmit = el.getAttribute("type") === "submit" || label.length > 0;
    if (!isSubmit || NOT_SUBMIT.test(label)) return;
    const c = fromNode(el, findCredentials);
    if (c) send(c); else fromNode(el, (n) => { rememberStep(n); return false; });
  }, true);

  document.addEventListener("keydown", (e) => {
    const t = origin(e);
    if (e.key !== "Enter" || !trusted(e) || !t || t.tagName !== "INPUT") return;
    const c = fromNode(t, findCredentials);
    if (c) send(c); else fromNode(t, (n) => { rememberStep(n); return false; });
  }, true);

  // ---------------------------------------------------------------------------------------------
  // Sugerencia de contraseña segura en formularios de registro y de cambio de contraseña.
  // Se genera aquí mismo (crypto.getRandomValues), sin depender de que el Gestor esté abierto.
  // ---------------------------------------------------------------------------------------------
  const LOWER = "abcdefghijklmnopqrstuvwxyz", UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
  const DIGITS = "0123456789", SYMBOLS = "!@#$%&*?-_+=";

  function randInt(n) { // entero uniforme en [0, n) sin sesgo
    const a = new Uint32Array(1), limit = Math.floor(0x100000000 / n) * n;
    do { crypto.getRandomValues(a); } while (a[0] >= limit);
    return a[0] % n;
  }

  // Mismas reglas que el Gestor: 16 caracteres con minúscula, mayúscula, número y símbolo.
  function generatePassword(length = 16) {
    const pools = [LOWER, UPPER, DIGITS, SYMBOLS], all = pools.join("");
    const chars = pools.map((p) => p[randInt(p.length)]);
    while (chars.length < length) chars.push(all[randInt(all.length)]);
    for (let i = chars.length - 1; i > 0; i--) { // Fisher-Yates
      const j = randInt(i + 1);
      [chars[i], chars[j]] = [chars[j], chars[i]];
    }
    return chars.join("");
  }

  const CUR_HINT = /current|actual|old|anterior|antigu|existing/i;
  const SIGNUP_HINT = /sign ?up|register|registr|crear (una )?cuenta|create (an )?account|alta\b|join|únete|hazte miembro|nueva cuenta|new account|nueva contrase|new password|cambi(a|ar) (la )?contrase|change (your )?password|restablec|reset (your )?password/i;
  const isCurrent = (i) => /current-password/.test(i.autocomplete) || CUR_HINT.test(attrs(i));

  // Contenedor del formulario al que pertenece el campo (<form>, o el bloque más alto con ≤ 3 contraseñas).
  function groupRoot(input) {
    if (input.form) return input.form;
    let best = null, node = input;
    for (let n = 0; node && n < 10; n++, node = parentOf(node)) {
      if (collect(node).filter((i) => i.type === "password" && visible(i)).length > 3) break;
      best = node;
    }
    return best || input.parentElement || document.body;
  }

  function contextText(root) {
    const bits = [location.pathname, document.title, root.id, String(root.className || "")];
    if (root.getAttribute) bits.push(root.getAttribute("action"), root.getAttribute("aria-label"));
    if (root.querySelectorAll) {
      root.querySelectorAll("h1,h2,h3,legend,button,[type=submit]").forEach((e) => bits.push(e.textContent || e.value));
    }
    return bits.filter(Boolean).join(" ");
  }

  // Campos que se rellenarían si `input` es una contraseña NUEVA (registro / cambio); null si no lo es.
  function suggestionTargets(input) {
    if (isCurrent(input)) return null; // la contraseña actual nunca se sugiere
    const root = groupRoot(input);
    const pwds = collect(root).filter((i) => i.type === "password" && visible(i));
    const newOnes = pwds.filter((i) => /new-password/.test(i.autocomplete));
    let targets;
    if (newOnes.length) targets = newOnes;
    else if (pwds.length >= 3) targets = pwds.slice(1);   // actual + nueva + confirmación
    else if (pwds.length === 2) targets = pwds;           // contraseña + confirmación
    else if (SIGNUP_HINT.test(contextText(root))) targets = pwds;   // registro con un solo campo
    else return null;
    targets = targets.filter((i) => !isCurrent(i));
    return targets.includes(input) ? targets : null;
  }

  function setValue(el, value) { // compatible con React/Vue: usa el setter nativo y avisa a la página
    Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true }));
    el.dispatchEvent(new Event("change", { bubbles: true }));
  }

  let panel = null;
  function closePanel() {
    if (!panel) return;
    panel.host.remove();
    window.removeEventListener("scroll", place, true);
    window.removeEventListener("resize", place, true);
    panel = null;
  }

  function place() {
    if (!panel) return;
    const r = panel.input.getBoundingClientRect();
    if (!r.width && !r.height) return closePanel();
    const h = panel.host.offsetHeight || 120;
    const below = r.bottom + 6 + h < window.innerHeight;
    panel.host.style.left = Math.max(6, Math.min(r.left, window.innerWidth - 330)) + "px";
    panel.host.style.top = (below ? r.bottom + 6 : Math.max(6, r.top - h - 6)) + "px";
  }

  function openPanel(input, targets) {
    closePanel();
    const host = document.createElement("div");
    host.setAttribute("data-gestor", "sugerencia");
    host.style.cssText = "all:initial;position:fixed;z-index:2147483647;left:0;top:0;";
    const root = host.attachShadow({ mode: "closed" });
    root.innerHTML = `
      <style>
        .box{box-sizing:border-box;width:320px;padding:12px 14px;border-radius:12px;background:#171a2e;color:#e8eaf6;
             border:1px solid #6c7bff;box-shadow:0 10px 30px rgba(0,0,0,.45);font:13px/1.4 "Segoe UI",system-ui,sans-serif}
        .t{color:#9096b8;font-size:11px;margin-bottom:6px}
        .pw{font:600 15px Consolas,monospace;color:#b9c0ff;background:#0f1220;border-radius:8px;padding:8px 10px;
            word-break:break-all;user-select:all}
        .row{display:flex;gap:8px;margin-top:10px}
        .b{flex:1;text-align:center;cursor:pointer;border-radius:8px;padding:7px 10px;font-weight:600;user-select:none}
        .use{background:#6c7bff;color:#fff}.use:hover{background:#8190ff}
        .re{flex:0 0 auto;background:#1e2240;color:#e8eaf6;border:1px solid #2a2f55}.re:hover{background:#262b52}
        .ok{color:#3ddc97;font-weight:600}
      </style>
      <div class="box"><div class="t">🔐 Gestor de contraseñas · contraseña segura sugerida</div>
        <div class="pw"></div>
        <div class="row"><div class="b use" role="button">Usar esta contraseña</div><div class="b re" role="button" title="Generar otra">↻</div></div>
      </div>`;
    const pwBox = root.querySelector(".pw");
    panel = { host, input, targets, pw: "" };
    const make = () => { panel.pw = generatePassword(); pwBox.textContent = panel.pw; };
    make();
    // mousedown sin acción por defecto: el campo conserva el foco y no se cierra el panel al pulsar
    root.querySelectorAll(".b").forEach((b) => b.addEventListener("mousedown", (e) => e.preventDefault()));
    root.querySelector(".re").addEventListener("click", make);
    root.querySelector(".use").addEventListener("click", () => {
      panel.filling = true; // nuestros propios eventos «input» no deben cerrar el panel
      targets.forEach((t) => setValue(t, panel.pw)); // contraseña y confirmación con el mismo valor
      panel.filling = false;
      root.querySelector(".t").innerHTML = '<span class="ok">✔ Rellenada: se guardará en el Gestor al enviar el formulario</span>';
      root.querySelector(".row").remove();
      setTimeout(closePanel, 1800);
    });
    document.documentElement.appendChild(host);
    place();
    window.addEventListener("scroll", place, true);
    window.addEventListener("resize", place, true);
    input.addEventListener("blur", () => setTimeout(() => { if (panel && panel.input === input) closePanel(); }, 200), { once: true });
  }

  document.addEventListener("focusin", (e) => {
    const el = origin(e);
    if (!el || el.tagName !== "INPUT" || el.type !== "password" || !visible(el) || el.value || el.readOnly || el.disabled) return;
    if (panel && panel.input === el) return;
    const targets = suggestionTargets(el);
    if (targets) openPanel(el, targets);
  }, true);
  document.addEventListener("keydown", (e) => { if (e.key === "Escape" && panel) closePanel(); }, true);
  document.addEventListener("input", (e) => { // si escribes tú, el panel sobra
    if (panel && origin(e) === panel.input && panel.input.value && !panel.filling) closePanel();
  }, true);
})();
