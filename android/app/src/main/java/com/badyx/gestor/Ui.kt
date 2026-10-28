package com.badyx.gestor

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Handler
import android.os.Looper
import android.os.PersistableBundle
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Card
import androidx.compose.material3.CardDefaults
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.FilterChip
import androidx.compose.material3.FloatingActionButton
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.Scaffold
import androidx.compose.material3.SnackbarHost
import androidx.compose.material3.SnackbarHostState
import androidx.compose.material3.Surface
import androidx.compose.material3.Tab
import androidx.compose.material3.TabRow
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.material3.TopAppBar
import androidx.compose.material3.TopAppBarDefaults
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.input.key.onPreviewKeyEvent
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

val BgColor = Color(0xFF0F1220)
val PanelColor = Color(0xFF171A2E)
val Panel2Color = Color(0xFF1E2240)
val LineColor = Color(0xFF2A2F55)
val TextColor = Color(0xFFE8EAF6)
val MutedColor = Color(0xFF9096B8)
val AccentColor = Color(0xFF6C7BFF)
val DangerColor = Color(0xFFFF5D73)
val OkColor = Color(0xFF3DDC97)
val WarnColor = Color(0xFFFFB347)

@Composable
fun GestorTheme(content: @Composable () -> Unit) = MaterialTheme(
    colorScheme = darkColorScheme(
        primary = AccentColor, onPrimary = Color.White, background = BgColor, onBackground = TextColor,
        surface = PanelColor, onSurface = TextColor, surfaceVariant = Panel2Color, onSurfaceVariant = MutedColor,
        error = DangerColor, outline = LineColor, secondaryContainer = AccentColor, onSecondaryContainer = Color.White,
    ),
    content = content,
)

@Composable
fun Root(vm: AppViewModel, onScan: () -> Unit) {
    Surface(Modifier.fillMaxSize(), color = BgColor) {
        when (vm.stage) {
            Stage.NEEDS_PAIR -> PairScreen(vm, onScan)
            Stage.LOCKED -> UnlockScreen(vm)
            Stage.UNLOCKED -> MainScreen(vm)
        }
    }
}

@Composable
private fun Centered(content: @Composable () -> Unit) = Column(
    Modifier.fillMaxSize().verticalScroll(rememberScrollState()).padding(28.dp),
    verticalArrangement = Arrangement.Center, horizontalAlignment = Alignment.CenterHorizontally,
) { content() }

@Composable
private fun PairScreen(vm: AppViewModel, onScan: () -> Unit) {
    var link by rememberSaveable { mutableStateOf("") }
    var pw by remember { mutableStateOf("") }
    val incoming = vm.pendingLink
    LaunchedEffect(incoming) { if (incoming != null) { link = incoming; vm.pendingLink = null } }
    Centered {
        Text("🔐", fontSize = 48.sp)
        Text("Vincular con tu PC", fontSize = 22.sp, fontWeight = FontWeight.Bold)
        Spacer(Modifier.height(8.dp))
        Text(
            "En el Gestor del PC: Administrador → Sincronizar con el móvil → Vincular un móvil. " +
                "Escanea el QR (el móvil y el PC deben estar en la misma Wi-Fi).",
            color = MutedColor, textAlign = TextAlign.Center,
        )
        Spacer(Modifier.height(16.dp))
        Button(onClick = onScan, Modifier.fillMaxWidth()) { Text("📷  Escanear QR") }
        Spacer(Modifier.height(10.dp))
        OutlinedTextField(link, { link = it }, Modifier.fillMaxWidth(), label = { Text("…o pega aquí el enlace de vinculación") },
            singleLine = true)
        Spacer(Modifier.height(10.dp))
        OutlinedTextField(pw, { pw = it }, Modifier.fillMaxWidth(), label = { Text("Contraseña maestra del PC") },
            singleLine = true, visualTransformation = PasswordVisualTransformation(),
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
            keyboardActions = KeyboardActions(onDone = { if (link.isNotBlank() && pw.isNotEmpty()) vm.pairAndDownload(link, pw) }))
        vm.error?.let { Text(it, color = DangerColor, modifier = Modifier.padding(top = 8.dp), textAlign = TextAlign.Center) }
        Spacer(Modifier.height(14.dp))
        Button(onClick = { vm.pairAndDownload(link, pw) }, Modifier.fillMaxWidth(),
            enabled = !vm.busy && link.isNotBlank() && pw.isNotEmpty()) {
            if (vm.busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = Color.White)
            else Text("Vincular y descargar")
        }
        Text("La contraseña maestra no sale del móvil: solo sirve para abrir tus datos aquí.",
            color = MutedColor, fontSize = 12.sp, textAlign = TextAlign.Center, modifier = Modifier.padding(top = 10.dp))
    }
}

@Composable
private fun UnlockScreen(vm: AppViewModel) {
    var pw by remember { mutableStateOf("") }
    var confirmWipe by remember { mutableStateOf(false) }
    var capsKey by remember { mutableStateOf(false) }
    val locked = vm.lockRemaining > 0
    LaunchedEffect(locked) { if (locked) pw = "" }
    // Bloq Mayús: con teclado físico se detecta; con teclado en pantalla Android no lo expone, así que se avisa
    // si lo escrito parece estar todo en mayúsculas.
    val letters = pw.filter { it.isLetter() }
    val allUpper = letters.length >= 3 && letters.all { it.isUpperCase() }
    Centered {
        Text("🔐", fontSize = 48.sp)
        if (!locked) { // bloqueada: se ocultan el título y el campo; al acabar el bloqueo vuelve todo
            Text("Desbloquear", fontSize = 22.sp, fontWeight = FontWeight.Bold)
            Spacer(Modifier.height(16.dp))
            OutlinedTextField(pw, { pw = it }, Modifier.fillMaxWidth().onPreviewKeyEvent { e ->
                capsKey = e.nativeKeyEvent.isCapsLockOn; false
            }, label = { Text("Contraseña maestra") },
                singleLine = true, visualTransformation = PasswordVisualTransformation(),
                keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                keyboardActions = KeyboardActions(onDone = { if (pw.isNotEmpty()) { vm.unlock(pw); pw = "" } }))
        }
        if (!locked && (capsKey || allUpper)) {
            Text(if (capsKey) "⚠ El bloqueo de mayúsculas está activado" else "⚠ Parece que escribes todo en mayúsculas: ¿está activado Bloq Mayús?",
                color = WarnColor, fontSize = 13.sp, textAlign = TextAlign.Center, modifier = Modifier.padding(top = 8.dp))
        }
        val left = if (locked) 0 else vm.attemptsLeft
        Text("Intentos disponibles: $left de $LOCK_ATTEMPTS", color = if (left <= 1) DangerColor else MutedColor,
            fontSize = 13.sp, modifier = Modifier.padding(top = 8.dp))
        if (locked) {
            Text("🔒 La aplicación está bloqueada.\nTiempo restante: ${LockGuard.format(vm.lockRemaining)}",
                color = DangerColor, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center,
                modifier = Modifier.padding(top = 10.dp))
        } else {
            vm.error?.let { Text(it, color = DangerColor, modifier = Modifier.padding(top = 8.dp)) }
        }
        Spacer(Modifier.height(14.dp))
        if (!locked) Button(onClick = { vm.unlock(pw); pw = "" }, Modifier.fillMaxWidth(), enabled = !vm.busy && pw.isNotEmpty()) {
            if (vm.busy) CircularProgressIndicator(Modifier.size(18.dp), strokeWidth = 2.dp, color = Color.White)
            else Text("Entrar")
        }
        TextButton(onClick = { confirmWipe = true }, Modifier.padding(top = 12.dp)) {
            Text("Olvidar los datos de este móvil", color = MutedColor, fontSize = 12.sp)
        }
    }
    if (confirmWipe) AlertDialog(
        onDismissRequest = { confirmWipe = false },
        title = { Text("¿Olvidar los datos de este móvil?") },
        text = { Text("Se borra el almacén y la vinculación del teléfono. Tus contraseñas siguen en el PC y podrás volver a vincular.") },
        confirmButton = { TextButton(onClick = { confirmWipe = false; vm.wipeAll() }) { Text("Borrar", color = DangerColor) } },
        dismissButton = { TextButton(onClick = { confirmWipe = false }) { Text("Cancelar") } },
    )
}

private fun copySensitive(ctx: Context, text: String) {
    val cm = ctx.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
    val clip = ClipData.newPlainText("contraseña", text)
    clip.description.extras = PersistableBundle().apply { putBoolean("android.content.extra.IS_SENSITIVE", true) }
    cm.setPrimaryClip(clip)
    // se borra sola a los 30 s si sigue siendo lo mismo
    Handler(Looper.getMainLooper()).postDelayed({
        val cur = cm.primaryClip?.getItemAt(0)?.text?.toString()
        if (cur == text) cm.setPrimaryClip(ClipData.newPlainText("", ""))
    }, 30_000)
}

private fun openWeb(ctx: Context, text: String) {
    var u = text.trim()
    if ("://" !in u) u = "https://$u"
    val uri = Uri.parse(u)
    if (uri.scheme != "http" && uri.scheme != "https") return
    ctx.startActivity(Intent(Intent.ACTION_VIEW, uri).addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
}

@OptIn(ExperimentalMaterial3Api::class)
@Composable
private fun MainScreen(vm: AppViewModel) {
    val ctx = LocalContext.current
    var tab by rememberSaveable { mutableIntStateOf(0) }
    var query by rememberSaveable { mutableStateOf("") }
    var editing by remember { mutableStateOf<Entry?>(null) }
    var showEdit by remember { mutableStateOf(false) }
    var deleting by remember { mutableStateOf<Entry?>(null) }
    var showSettings by remember { mutableStateOf(false) }
    val snack = remember { SnackbarHostState() }
    LaunchedEffect(vm.message) {
        vm.message?.let { snack.showSnackbar(it); vm.message = null }
    }
    Scaffold(
        containerColor = BgColor,
        snackbarHost = { SnackbarHost(snack) },
        topBar = {
            TopAppBar(
                title = { Text("Mis claves", fontWeight = FontWeight.Bold) },
                colors = TopAppBarDefaults.topAppBarColors(containerColor = PanelColor, titleContentColor = TextColor),
                actions = {
                    IconButton(onClick = { vm.syncNow() }, enabled = vm.pairing != null && !vm.syncing) {
                        if (vm.syncing) CircularProgressIndicator(Modifier.size(20.dp), strokeWidth = 2.dp)
                        else Text("🔄", fontSize = 20.sp)
                    }
                    IconButton(onClick = { vm.lockNow() }) { Text("🔒", fontSize = 20.sp) }
                    IconButton(onClick = { showSettings = true }) { Text("⚙", fontSize = 20.sp) }
                },
            )
        },
        floatingActionButton = {
            if (tab < 2) FloatingActionButton(onClick = { editing = null; showEdit = true }, containerColor = AccentColor,
                contentColor = Color.White) { Text("+", fontSize = 28.sp) }
        },
    ) { pad ->
        LaunchedEffect(tab, vm.deniedVersion) { if (tab == 2) vm.markDeniedSeen() }
        Column(Modifier.padding(pad).fillMaxSize()) {
            TabRow(selectedTabIndex = tab, containerColor = PanelColor, contentColor = AccentColor) {
                Tab(selected = tab == 0, onClick = { tab = 0 }, text = { Text("✉ Correos (${vm.count(0)})", fontSize = 13.sp) })
                Tab(selected = tab == 1, onClick = { tab = 1 }, text = { Text("🌐 Webs (${vm.count(1)})", fontSize = 13.sp) })
                Tab(selected = tab == 2, onClick = { tab = 2 },
                    text = { Text((if (vm.deniedUnseen > 0 && tab != 2) "⚠" else "🚫") + " Accesos", fontSize = 13.sp) })
            }
            if (tab == 2) { DeniedPanel(vm); return@Column }
            OutlinedTextField(query, { query = it }, Modifier.fillMaxWidth().padding(12.dp, 10.dp, 12.dp, 4.dp),
                placeholder = { Text("🔍  Buscar") }, singleLine = true,
                trailingIcon = { if (query.isNotEmpty()) TextButton(onClick = { query = "" }) { Text("✕") } })
            val list = vm.entries(tab, query)
            if (list.isEmpty()) {
                Box(Modifier.fillMaxSize(), contentAlignment = Alignment.Center) {
                    Text(if (query.isBlank()) "Aún no hay nada guardado.\nPulsa + para añadir." else "Ningún resultado",
                        color = MutedColor, textAlign = TextAlign.Center)
                }
            } else LazyColumn(Modifier.fillMaxSize(), contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp, 4.dp, 12.dp, 96.dp),
                verticalArrangement = Arrangement.spacedBy(8.dp)) {
                items(list, key = { it.id }) { e ->
                    EntryCard(e, tab == 1, vm.isRepeated(e),
                        onEdit = { editing = e; showEdit = true }, onDelete = { deleting = e })
                }
            }
        }
    }
    if (showEdit) EditDialog(editing, onDismiss = { showEdit = false }) { u, p, a, n ->
        vm.save(editing, tab, u, p, a, n); showEdit = false
    }
    deleting?.let { e ->
        AlertDialog(
            onDismissRequest = { deleting = null },
            title = { Text("Eliminar") },
            text = { Text("¿Eliminar «${e.user}»? Se borrará también en el PC al sincronizar.") },
            confirmButton = { TextButton(onClick = { vm.delete(e, tab); deleting = null }) { Text("Eliminar", color = DangerColor) } },
            dismissButton = { TextButton(onClick = { deleting = null }) { Text("Cancelar") } },
        )
    }
    if (showSettings) SettingsDialog(vm) { showSettings = false }
}

@Composable
private fun DeniedPanel(vm: AppViewModel) {
    val rows = vm.deniedRows()
    var confirm by remember { mutableStateOf(false) }
    Column(Modifier.fillMaxSize()) {
        Text("Accesos denegados: intentos de desbloqueo con una contraseña incorrecta, del más reciente al más antiguo. " +
            "Las contraseñas pueden parecerse a la real: se guardan cifradas y solo se ven con la app desbloqueada.",
            color = MutedColor, fontSize = 12.sp, modifier = Modifier.padding(14.dp, 12.dp, 14.dp, 4.dp))
        Row(Modifier.fillMaxWidth().padding(horizontal = 14.dp), verticalAlignment = Alignment.CenterVertically) {
            Text(if (rows.isEmpty()) "✅ Ningún intento fallido." else "${rows.size} intento${if (rows.size != 1) "s" else ""} registrado${if (rows.size != 1) "s" else ""}",
                color = if (rows.isEmpty()) OkColor else DangerColor, fontWeight = FontWeight.SemiBold, modifier = Modifier.weight(1f))
            if (rows.isNotEmpty()) TextButton(onClick = { confirm = true }) { Text("Borrar registro", color = DangerColor) }
        }
        LazyColumn(Modifier.fillMaxSize(), contentPadding = androidx.compose.foundation.layout.PaddingValues(12.dp, 4.dp, 12.dp, 24.dp),
            verticalArrangement = Arrangement.spacedBy(8.dp)) {
            items(rows, key = { it.id }) { r ->
                Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = Panel2Color)) {
                    Column(Modifier.padding(14.dp)) {
                        Text(formatDate(r.time), color = MutedColor, fontSize = 12.sp)
                        Text(r.password ?: "(no registrada)", fontFamily = FontFamily.Monospace, color = DangerColor,
                            fontSize = 16.sp, fontWeight = FontWeight.SemiBold, modifier = Modifier.padding(vertical = 2.dp))
                        Text("🌍 IP: ${r.ip.ifBlank { "—" }}" + if (r.lan.isNotBlank()) "  (red local ${r.lan})" else "", fontSize = 13.sp)
                        Text("📍 ${r.location.ifBlank { "Ubicación desconocida" }}", fontSize = 13.sp)
                        Text("📱 ${r.device}", fontSize = 13.sp, color = MutedColor)
                    }
                }
            }
        }
    }
    if (confirm) AlertDialog(
        onDismissRequest = { confirm = false },
        title = { Text("Borrar registro") },
        text = { Text("¿Borrar todos los intentos registrados? No se puede deshacer.") },
        confirmButton = { TextButton(onClick = { confirm = false; vm.clearDenied() }) { Text("Borrar", color = DangerColor) } },
        dismissButton = { TextButton(onClick = { confirm = false }) { Text("Cancelar") } },
    )
}

@Composable
private fun EntryCard(e: Entry, isWeb: Boolean, repeated: Boolean, onEdit: () -> Unit, onDelete: () -> Unit) {
    val ctx = LocalContext.current
    var show by remember { mutableStateOf(false) }
    Card(Modifier.fillMaxWidth(), colors = CardDefaults.cardColors(containerColor = Panel2Color)) {
        Column(Modifier.padding(14.dp)) {
            Text(e.user, fontWeight = FontWeight.SemiBold, fontSize = 16.sp)
            if (e.alias.isNotBlank()) Text("👤 ${e.alias}", color = MutedColor, fontSize = 13.sp)
            Spacer(Modifier.height(6.dp))
            Row(verticalAlignment = Alignment.CenterVertically) {
                Text(if (show) e.pass else "•".repeat(minOf(e.pass.length, 14)), fontFamily = FontFamily.Monospace,
                    color = Color(0xFFB9C0FF), fontSize = 15.sp)
                // fortaleza de la contraseña: barra de 4 tramos y nivel
                val lvl = strength(e.pass)
                val col = listOf(MutedColor, DangerColor, WarnColor, Color(0xFF7ED957), OkColor)[lvl]
                Spacer(Modifier.width(12.dp))
                Row(horizontalArrangement = Arrangement.spacedBy(2.dp)) {
                    for (k in 0 until 4) Box(Modifier.size(10.dp, 4.dp).background(if (k < lvl) col else LineColor))
                }
                Spacer(Modifier.width(6.dp))
                Text(listOf("", "Débil", "Media", "Fuerte", "Muy fuerte")[lvl], color = col, fontSize = 11.sp,
                    fontWeight = FontWeight.SemiBold)
            }
            val dates = buildString {
                if (e.created.isNotBlank()) append("Creado ${formatDate(e.created)}")
                if (e.modified.isNotBlank()) append(if (isNotEmpty()) "  ·  ✏ ${formatDate(e.modified)}" else "✏ ${formatDate(e.modified)}")
            }
            if (dates.isNotEmpty()) Text(dates, color = MutedColor, fontSize = 11.sp, modifier = Modifier.padding(top = 4.dp))
            if (repeated) Text("⚠ contraseña repetida", color = WarnColor, fontSize = 11.sp)
            if (e.notes.isNotBlank()) Text("📝 ${e.notes}", color = MutedColor, fontSize = 12.sp, modifier = Modifier.padding(top = 4.dp))
            val pad = androidx.compose.foundation.layout.PaddingValues(horizontal = 14.dp)
            val h = Modifier.height(36.dp)
            Row(Modifier.fillMaxWidth().padding(top = 2.dp), horizontalArrangement = Arrangement.End) {
                if (isWeb) TextButton(onClick = { openWeb(ctx, e.user) }, h, contentPadding = pad) { Text("↗") }
                TextButton(onClick = { show = !show }, h, contentPadding = pad) { Text(if (show) "🙈" else "👁") }
                TextButton(onClick = { copySensitive(ctx, e.pass) }, h, contentPadding = pad) { Text("📋") }
                TextButton(onClick = onEdit, h, contentPadding = pad) { Text("✏") }
                TextButton(onClick = onDelete, h, contentPadding = pad) { Text("🗑", color = DangerColor) }
            }
        }
    }
}

@Composable
private fun EditDialog(entry: Entry?, onDismiss: () -> Unit, onSave: (String, String, String, String) -> Unit) {
    var user by remember { mutableStateOf(entry?.user ?: "") }
    var pass by remember { mutableStateOf(entry?.pass ?: "") }
    var alias by remember { mutableStateOf(entry?.alias ?: "") }
    var notes by remember { mutableStateOf(entry?.notes ?: "") }
    var err by remember { mutableStateOf(false) }
    val level = strength(pass)
    val labels = listOf("", "Débil", "Media", "Fuerte", "Muy fuerte")
    val colors = listOf(MutedColor, DangerColor, WarnColor, Color(0xFF7ED957), OkColor)
    AlertDialog(
        onDismissRequest = onDismiss,
        title = { Text(if (entry == null) "Añadir" else "Editar") },
        text = {
            Column(Modifier.verticalScroll(rememberScrollState())) {
                OutlinedTextField(user, { user = it }, Modifier.fillMaxWidth(), label = { Text("Correo o web *") },
                    singleLine = true, isError = err && user.isBlank())
                OutlinedTextField(pass, { pass = it }, Modifier.fillMaxWidth().padding(top = 8.dp), label = { Text("Contraseña *") },
                    singleLine = true, isError = err && pass.isBlank())
                Row(Modifier.fillMaxWidth(), verticalAlignment = Alignment.CenterVertically) {
                    Text(labels[level], color = colors[level], fontSize = 12.sp, modifier = Modifier.weight(1f))
                    TextButton(onClick = { pass = generatePassword() }) { Text("🎲 Generar segura") }
                }
                OutlinedTextField(alias, { alias = it }, Modifier.fillMaxWidth(), label = { Text("Usuario / alias (opcional)") }, singleLine = true)
                OutlinedTextField(notes, { notes = it }, Modifier.fillMaxWidth().padding(top = 8.dp), label = { Text("Notas (opcional)") }, minLines = 2)
                if (err) Text("Los campos obligatorios no pueden estar vacíos.", color = DangerColor, fontSize = 12.sp)
            }
        },
        confirmButton = {
            TextButton(onClick = {
                if (user.isBlank() || pass.isBlank()) err = true else onSave(user.trim(), pass.trim(), alias.trim(), notes.trim())
            }) { Text("Aceptar") }
        },
        dismissButton = { TextButton(onClick = onDismiss) { Text("Cancelar") } },
    )
}

@Composable
private fun SettingsDialog(vm: AppViewModel, onClose: () -> Unit) {
    var confirmUnpair by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = onClose,
        title = { Text("Ajustes") },
        text = {
            Column {
                val p = vm.pairing
                Text(if (p != null) "📡 Vinculado con el PC (${p.lastHost.ifBlank { p.hosts.firstOrNull() ?: "" }})" else "Sin vincular: los cambios solo se guardan en este móvil.",
                    fontWeight = FontWeight.SemiBold)
                Text(if (vm.lastSync.isNotBlank()) "Última sincronización: ${formatDate(vm.lastSync)}" else "Aún no se ha sincronizado.",
                    color = MutedColor, fontSize = 13.sp, modifier = Modifier.padding(top = 2.dp))
                if (p != null) {
                    Row(Modifier.padding(top = 8.dp)) {
                        OutlinedButton(onClick = { vm.syncNow() }, enabled = !vm.syncing) { Text("Sincronizar ahora") }
                        Spacer(Modifier.width(8.dp))
                        OutlinedButton(onClick = { confirmUnpair = true },
                            colors = ButtonDefaults.outlinedButtonColors(contentColor = DangerColor)) { Text("Desvincular") }
                    }
                }
                Text("Bloqueo automático al salir de la app", modifier = Modifier.padding(top = 16.dp), fontWeight = FontWeight.SemiBold)
                Row(Modifier.padding(top = 4.dp), horizontalArrangement = Arrangement.spacedBy(6.dp)) {
                    for ((m, label) in listOf(0 to "Al instante", 1 to "1 min", 5 to "5 min", -1 to "Nunca")) {
                        val sel = (m == -1 && vm.autoLockMinutes < 0) || (m != -1 && vm.autoLockMinutes == m)
                        FilterChip(selected = sel, onClick = { vm.setAutoLock(if (m == -1) -1 else m) }, label = { Text(label, fontSize = 12.sp) })
                    }
                }
            }
        },
        confirmButton = { TextButton(onClick = onClose) { Text("Cerrar") } },
    )
    if (confirmUnpair) AlertDialog(
        onDismissRequest = { confirmUnpair = false },
        title = { Text("¿Desvincular?") },
        text = { Text("Este móvil dejará de sincronizar con el PC. Tus datos se conservan en el teléfono.") },
        confirmButton = { TextButton(onClick = { confirmUnpair = false; vm.unpair() }) { Text("Desvincular", color = DangerColor) } },
        dismissButton = { TextButton(onClick = { confirmUnpair = false }) { Text("Cancelar") } },
    )
}
