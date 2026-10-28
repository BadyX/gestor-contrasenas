package com.badyx.gestor

import android.app.Application
import android.os.Build
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableLongStateOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import java.io.File

enum class Stage { NEEDS_PAIR, LOCKED, UNLOCKED }

class AppViewModel(app: Application) : AndroidViewModel(app) {
    private val vaultFile = VaultFile(File(app.filesDir, "vault.dat"))
    private val pairingStore = PairingStore(File(app.filesDir, "pairing.json"))
    private val prefs = app.getSharedPreferences("gestor", 0)
    private val guard = LockGuard(object : KV {
        override fun getString(k: String) = prefs.getString(k, null)
        override fun putString(k: String, v: String) { prefs.edit().putString(k, v).apply() }
    })
    private val deniedLog = DeniedLog(File(app.filesDir, "denied.json"), KeystorePending())

    // ---- antifuerza bruta ----
    var lockRemaining by mutableLongStateOf(guard.remaining()); private set   // segundos de bloqueo que faltan
    var attemptsLeft by mutableIntStateOf(guard.attemptsLeft()); private set
    var deniedUnseen by mutableIntStateOf(0); private set
    var deniedVersion by mutableIntStateOf(0); private set

    init {
        refreshDeniedUnseen()
        viewModelScope.launch {
            while (true) { // actualiza la cuenta atrás cada segundo
                lockRemaining = guard.remaining()
                attemptsLeft = guard.attemptsLeft()
                delay(1000)
            }
        }
    }

    private fun refreshDeniedUnseen() {
        deniedUnseen = deniedLog.unseen(prefs.getString("denied_seen", "") ?: "")
    }

    private fun deviceLabel() =
        "Móvil · ${Build.MANUFACTURER.replaceFirstChar { it.uppercase() }} ${Build.MODEL} · Android ${Build.VERSION.RELEASE}"

    private fun recordDenied(password: String) {
        val pub = prefs.getString("deny_pub", "") ?: ""
        viewModelScope.launch(Dispatchers.IO) {
            deniedLog.record(pub, password, deviceLabel(), lanIp(), ::geoLookup)
            pushDenied() // avisa al PC enseguida, aunque este móvil siga bloqueado
            withContext(Dispatchers.Main) { refreshDeniedUnseen(); deniedVersion++ }
        }
    }

    /** Envía al PC los intentos fallidos (cifrados con la clave pública; no hace falta la contraseña maestra). */
    private fun pushDenied() {
        val p = pairing ?: return
        try { Sync.denied(p, deniedLog.synced()) } catch (e: Exception) { /* sin PC a mano: irán en la próxima sincronización */ }
    }

    /**
     * Procesa lo que el PC envía junto a los datos: sus intentos fallidos y la clave del registro. Si la clave
     * es distinta de la de este móvil se adopta (volviendo a sellar los intentos propios) para que los dos
     * dispositivos puedan leer los intentos del otro. Devuelve true si se cambió la clave.
     */
    private fun applyRemoteExtras(remote: VaultData): Boolean {
        val list = remote.extraArray("denied")
        if (list != null) {
            val added = deniedLog.mergeIn((0 until list.length()).mapNotNull { list.optJSONObject(it) }, data.deleted)
            if (added > 0) {
                refreshDeniedUnseen(); deniedVersion++
                message = "⚠ $added intento${if (added != 1) "s" else ""} de acceso fallido${if (added != 1) "s" else ""} registrado${if (added != 1) "s" else ""} en el PC"
            }
        }
        val newPriv = remote.extraString("denykey")
        val oldPriv = data.extraString("denykey")
        if (newPriv.isEmpty() || newPriv == oldPriv) return false
        val newPub = Seal.pubOf(newPriv)
        if (oldPriv.isNotEmpty()) deniedLog.reseal(oldPriv, newPub)
        data.extraPut("denykey", newPriv)
        prefs.edit().putString("deny_pub", newPub).apply()
        val k = key; val s = salt
        if (k != null && s != null) vaultFile.write(Crypto.pack(k, s, data.toJson().toString()))
        deniedVersion++
        return true
    }

    /** Par de claves del registro: la privada vive dentro del almacén cifrado y la pública en los ajustes. */
    private fun ensureDenyKey() {
        if (data.extraString("denykey").isEmpty()) {
            data.extraPut("denykey", Seal.keypair().first)
            val k = key; val s = salt
            if (k != null && s != null) vaultFile.write(Crypto.pack(k, s, data.toJson().toString()))
        }
        val pub = Seal.pubOf(data.extraString("denykey"))
        prefs.edit().putString("deny_pub", pub).apply()
        deniedLog.migrate(pub) // intentos anteriores a tener clave: ya con su contraseña, cifrados
    }

    fun deniedRows(): List<DeniedRow> {
        deniedVersion
        val priv = data.extraString("denykey")
        return if (priv.isEmpty()) emptyList() else deniedLog.read(priv)
    }

    fun markDeniedSeen() {
        prefs.edit().putString("denied_seen", nowIso()).apply()
        refreshDeniedUnseen()
    }

    fun clearDenied() {
        deniedLog.ids().forEach { data.deleted[it] = nowRev() } // lápidas: el borrado también llega al PC
        deniedLog.clear(); refreshDeniedUnseen(); deniedVersion++
        persist()
    }

    var stage by mutableStateOf(if (vaultFile.exists()) Stage.LOCKED else Stage.NEEDS_PAIR)
        private set
    var busy by mutableStateOf(false); private set
    var error by mutableStateOf<String?>(null)
    var message by mutableStateOf<String?>(null)
    var syncing by mutableStateOf(false); private set
    var lastSync by mutableStateOf(prefs.getString("lastSync", "") ?: ""); private set
    var pairing by mutableStateOf(pairingStore.load()); private set
    var autoLockMinutes by mutableIntStateOf(prefs.getInt("autoLock", 1)); private set
    var pendingLink by mutableStateOf<String?>(null)

    /** Se incrementa cada vez que cambian los datos, para que la interfaz se redibuje. */
    var version by mutableIntStateOf(0); private set

    private var data = VaultData()
    private var key: ByteArray? = null
    private var salt: ByteArray? = null
    private val lock = Mutex()
    private var syncJob: Job? = null
    private var loopJob: Job? = null
    private var leftAt = 0L

    fun entries(tab: Int, query: String): List<Entry> {
        version // lectura: hace que el llamante se actualice con los cambios
        val q = query.trim().lowercase()
        return data.section(tab)
            .filter { q.isEmpty() || (it.user + " " + it.alias + " " + it.notes).lowercase().contains(q) }
            .sortedByDescending { it.rev } // lo último tocado primero (rev es UTC: no depende de la zona horaria de cada dispositivo)
    }

    fun count(tab: Int): Int { version; return data.section(tab).size }

    /** Contraseñas repetidas dentro de todo el almacén (para marcar ⚠). */
    fun isRepeated(e: Entry): Boolean {
        version
        return (data.correos + data.webs).count { it.pass == e.pass } > 1
    }

    // ---- acceso ----
    fun unlock(password: String) {
        if (busy) return
        if (guard.remaining() > 0) { lockRemaining = guard.remaining(); return } // bloqueada: no se admite ninguna contraseña
        busy = true; error = null
        viewModelScope.launch {
            try {
                val blob = vaultFile.read()
                val (k, s, d) = withContext(Dispatchers.Default) {
                    val s = Crypto.saltOf(blob)
                    val k = Crypto.deriveKey(password, s)
                    Triple(k, s, VaultData.fromJson(Crypto.unpack(k, blob)))
                }
                key = k; salt = s; data = d; version++
                guard.registerSuccess(); lockRemaining = 0; attemptsLeft = guard.attemptsLeft()
                ensureDenyKey()
                stage = Stage.UNLOCKED
                if (deniedUnseen > 0) message = "⚠ $deniedUnseen intento${if (deniedUnseen != 1) "s" else ""} de acceso fallido${if (deniedUnseen != 1) "s" else ""}: mira «Accesos denegados»"
                startLoop()
            } catch (e: Crypto.WrongKeyException) {
                val secs = guard.registerFailure()
                recordDenied(password) // queda en «Accesos denegados» (cifrado)
                lockRemaining = guard.remaining(); attemptsLeft = guard.attemptsLeft()
                error = if (secs > 0) null else "Contraseña incorrecta"
            } catch (e: Exception) {
                error = "No se pudo abrir el almacén: ${e.message}"
            } finally {
                busy = false
            }
        }
    }

    fun lockNow() {
        loopJob?.cancel(); syncJob?.cancel()
        key = null; salt = null; data = VaultData(); version++
        if (stage == Stage.UNLOCKED) stage = Stage.LOCKED
    }

    fun onBackground() {
        leftAt = System.currentTimeMillis()
        if (stage == Stage.UNLOCKED && autoLockMinutes == 0) lockNow() // «Al instante»
    }

    fun onForeground() {
        if (stage == Stage.UNLOCKED && autoLockMinutes > 0 && leftAt > 0 &&
            System.currentTimeMillis() - leftAt > autoLockMinutes * 60_000L) lockNow()
        leftAt = 0
    }

    fun setAutoLock(minutes: Int) {
        autoLockMinutes = minutes
        prefs.edit().putInt("autoLock", minutes).apply()
    }

    // ---- vinculación con el PC ----
    /** Canjea el QR/enlace, descarga el almacén del PC y lo abre con la contraseña maestra. */
    fun pairAndDownload(linkText: String, password: String) {
        if (busy) return
        busy = true; error = null
        viewModelScope.launch {
            try {
                val (p, remote, k, s) = withContext(Dispatchers.IO) {
                    val link = Sync.parseLink(linkText)
                    val name = "${Build.MANUFACTURER} ${Build.MODEL}".trim().take(50)
                    val p = Sync.pair(link, name)
                    val blob = Sync.sync(p, null)
                    val s = Crypto.saltOf(blob)
                    val k = Crypto.deriveKey(password, s)
                    val d = VaultData.fromJson(Crypto.unpack(k, blob))
                    Quad(p, d, k, s).also { vaultFile.write(blob) }
                }
                pairingStore.save(p); pairing = p
                key = k; salt = s; data = VaultData(remote.correos, remote.webs, remote.deleted); version++
                applyRemoteExtras(remote) // adopta la clave del registro del PC y trae sus intentos
                ensureDenyKey()
                markSynced()
                stage = Stage.UNLOCKED
                message = "Vinculado con el PC"
                startLoop()
            } catch (e: Crypto.WrongKeyException) {
                // el PC ya vinculó este móvil, pero la contraseña no abre el almacén: se deshace
                pairingStore.clear(); pairing = null; vaultFile.delete()
                error = "Contraseña maestra incorrecta. Genera un QR nuevo en el PC e inténtalo de nuevo."
            } catch (e: SyncException) {
                error = e.message
            } catch (e: Exception) {
                error = "No se pudo vincular: ${e.message}"
            } finally {
                busy = false
            }
        }
    }

    /** Borra todo lo de este móvil (almacén y vinculación). Los datos siguen en el PC. */
    fun wipeAll() {
        lockNow()
        vaultFile.delete(); pairingStore.clear(); pairing = null
        stage = Stage.NEEDS_PAIR
    }

    fun unpair() {
        pairingStore.clear(); pairing = null
        message = "Móvil desvinculado (tus datos siguen en el teléfono)"
    }

    // ---- cambios ----
    fun save(entry: Entry?, tab: Int, user: String, pass: String, alias: String, notes: String) {
        if (entry == null) {
            data.section(tab).add(Entry.create(user, pass, alias, notes))
        } else {
            val old = entry.pass
            entry.user = user; entry.pass = pass; entry.alias = alias; entry.notes = notes
            entry.json.put("modified", nowIso())
            if (pass != old) entry.json.put("changed", nowIso())
            entry.rev = nowRev()
        }
        persist()
    }

    fun delete(entry: Entry, tab: Int) {
        data.deleted[entry.id] = nowRev()
        data.section(tab).removeAll { it.id == entry.id }
        persist()
    }

    private fun persist() {
        val k = key ?: return
        val s = salt ?: return
        vaultFile.write(Crypto.pack(k, s, data.toJson().toString()))
        version++
        scheduleSync()
    }

    // ---- sincronización ----
    private fun markSynced() {
        lastSync = nowIso()
        prefs.edit().putString("lastSync", lastSync).apply()
    }

    private fun scheduleSync() {
        if (pairing == null) return
        syncJob?.cancel()
        syncJob = viewModelScope.launch { delay(1500); syncNow(silent = true) }
    }

    private fun startLoop() {
        loopJob?.cancel()
        loopJob = viewModelScope.launch {
            syncNow(silent = true)
            while (true) { delay(90_000); syncNow(silent = true) }
        }
    }

    /** Sincroniza con el PC: envía los datos, recibe la fusión y la guarda. */
    fun syncNow(silent: Boolean = false) {
        viewModelScope.launch { doSync(silent) }
    }

    private suspend fun doSync(silent: Boolean) {
        val p = pairing ?: return
        val k = key ?: return
        val s = salt ?: return
        var keyChanged = false
        lock.withLock {
            syncing = true
            try {
                val mine = data.copy().toSyncJson(deniedLog.synced()).toString() // correos, webs, lápidas e intentos cifrados
                val reply = withContext(Dispatchers.IO) { Sync.sync(p, Crypto.pack(k, s, mine)) }
                val remote = VaultData.fromJson(withContext(Dispatchers.Default) { Crypto.unpack(k, reply) })
                data = mergeData(data, remote) // por si hubo cambios mientras se sincronizaba
                keyChanged = applyRemoteExtras(remote)
                vaultFile.write(Crypto.pack(k, s, data.toJson().toString()))
                pairingStore.save(p)
                markSynced(); version++
                if (!silent) message = "Sincronizado con el PC"
            } catch (e: SyncException) {
                if (e.kind == SyncException.Kind.AUTH) { pairingStore.clear(); pairing = null }
                if (!silent || e.kind != SyncException.Kind.NETWORK) message = e.message
            } catch (e: Crypto.WrongKeyException) {
                message = "No se pudo descifrar la respuesta del PC: ¿cambió la contraseña maestra? Vuelve a vincular."
            } catch (e: Exception) {
                if (!silent) message = "Error al sincronizar: ${e.message}"
            } finally {
                syncing = false
            }
        }
        // se adoptó la clave del registro: segunda ronda para enviar al PC los intentos propios ya re-sellados
        if (keyChanged) doSync(silent)
    }
}

private data class Quad<A, B, C, D>(val a: A, val b: B, val c: C, val d: D)
