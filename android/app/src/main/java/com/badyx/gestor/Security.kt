package com.badyx.gestor

import org.bouncycastle.crypto.agreement.X25519Agreement
import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.HKDFParameters
import org.bouncycastle.crypto.params.X25519PrivateKeyParameters
import org.bouncycastle.crypto.params.X25519PublicKeyParameters
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.NetworkInterface
import java.net.URL
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec
import kotlin.math.ceil
import kotlin.math.max

const val LOCK_ATTEMPTS = 2
const val DENIED_MAX = 500

private fun b64(b: ByteArray): String = Base64.getEncoder().encodeToString(b)
private fun unb64(s: String): ByteArray = Base64.getDecoder().decode(s)

/**
 * «Caja sellada» (X25519 + HKDF-SHA256 + AES-GCM), idéntica a la del PC: con la clave pública cualquiera puede
 * escribir un registro cifrado, pero solo la clave privada (guardada dentro del almacén cifrado) puede leerlo.
 * Así un intento fallido se registra sin conocer la contraseña maestra.
 */
object Seal {
    fun keypair(): Pair<String, String> {
        val priv = X25519PrivateKeyParameters(SecureRandom())
        return b64(priv.encoded) to b64(priv.generatePublicKey().encoded)
    }

    fun pubOf(privB64: String): String = b64(X25519PrivateKeyParameters(unb64(privB64), 0).generatePublicKey().encoded)

    private fun key(priv: X25519PrivateKeyParameters, pub: X25519PublicKeyParameters): ByteArray {
        val shared = ByteArray(32)
        X25519Agreement().apply { init(priv) }.calculateAgreement(pub, shared, 0)
        val out = ByteArray(32)
        HKDFBytesGenerator(SHA256Digest()).apply { init(HKDFParameters(shared, null, "gestor-denied-v1".toByteArray())) }
            .generateBytes(out, 0, 32)
        return out
    }

    fun seal(pubB64: String, json: String): String {
        val eph = X25519PrivateKeyParameters(SecureRandom())
        val k = key(eph, X25519PublicKeyParameters(unb64(pubB64), 0))
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, nonce))
        }
        return b64(eph.generatePublicKey().encoded + nonce + c.doFinal(json.toByteArray(Charsets.UTF_8)))
    }

    fun unseal(privB64: String, blobB64: String): String {
        val raw = unb64(blobB64)
        val k = key(X25519PrivateKeyParameters(unb64(privB64), 0), X25519PublicKeyParameters(raw.copyOfRange(0, 32), 0))
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, raw.copyOfRange(32, 44)))
        }
        return String(c.doFinal(raw.copyOfRange(44, raw.size)), Charsets.UTF_8)
    }
}

/** Almacén clave-valor mínimo (SharedPreferences en la app; un mapa en las pruebas). */
interface KV {
    fun getString(k: String): String?
    fun putString(k: String, v: String)
}

/**
 * Antifuerza bruta: 2 intentos; al fallar ambos, bloqueo de 10 min (1.º), 1 día (2.º) y un día más cada vez.
 * La «hora de referencia» nunca retrocede, así que atrasar el reloj del teléfono no acorta un bloqueo.
 */
class LockGuard(private val kv: KV) {
    private fun d(k: String) = kv.getString(k)?.toDoubleOrNull() ?: 0.0
    private fun i(k: String) = kv.getString(k)?.toIntOrNull() ?: 0

    fun now(nowSec: Double = System.currentTimeMillis() / 1000.0): Double {
        val eff = max(nowSec, d("lock_seen"))
        kv.putString("lock_seen", eff.toString())
        return eff
    }

    fun remaining(nowSec: Double = System.currentTimeMillis() / 1000.0): Long =
        max(0.0, ceil(d("lock_until") - now(nowSec))).toLong()

    fun attemptsLeft(): Int = max(0, LOCK_ATTEMPTS - i("lock_fails"))

    /** Devuelve los segundos de bloqueo aplicados (0 si todavía quedan intentos). */
    fun registerFailure(nowSec: Double = System.currentTimeMillis() / 1000.0): Long {
        val eff = now(nowSec)
        val fails = i("lock_fails") + 1
        if (fails >= LOCK_ATTEMPTS) {
            val count = i("lock_count") + 1
            val secs = lockSeconds(count)
            kv.putString("lock_count", count.toString())
            kv.putString("lock_until", (eff + secs).toString())
            kv.putString("lock_fails", "0")
            return secs
        }
        kv.putString("lock_fails", fails.toString())
        return 0
    }

    fun registerSuccess() {
        kv.putString("lock_fails", "0"); kv.putString("lock_count", "0"); kv.putString("lock_until", "0")
    }

    companion object {
        fun lockSeconds(count: Int): Long = if (count <= 1) 600L else (count - 1) * 86_400L

        fun format(sec: Long): String {
            val d = sec / 86_400; val h = sec % 86_400 / 3600; val m = sec % 3600 / 60; val s = sec % 60
            return when {
                d > 0 -> "$d día${if (d != 1L) "s" else ""} $h h ${"%02d".format(m)} min ${"%02d".format(s)} s"
                h > 0 -> "$h h ${"%02d".format(m)} min ${"%02d".format(s)} s"
                else -> "$m min ${"%02d".format(s)} s"
            }
        }
    }
}

class DeniedRow(val id: String, val time: String, val password: String?, val ip: String, val lan: String,
                val location: String, val device: String)

/** Protección sin contraseña maestra (Android Keystore), solo para los intentos anteriores a tener la clave del registro. */
interface Pending {
    fun protect(b: ByteArray): ByteArray
    fun unprotect(b: ByteArray): ByteArray
}

class KeystorePending : Pending {
    private val alias = "gestor_denied_pending"

    private fun key(): javax.crypto.SecretKey {
        val ks = java.security.KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        (ks.getKey(alias, null) as? javax.crypto.SecretKey)?.let { return it }
        val g = javax.crypto.KeyGenerator.getInstance(android.security.keystore.KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        g.init(
            android.security.keystore.KeyGenParameterSpec.Builder(
                alias,
                android.security.keystore.KeyProperties.PURPOSE_ENCRYPT or android.security.keystore.KeyProperties.PURPOSE_DECRYPT,
            ).setBlockModes(android.security.keystore.KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(android.security.keystore.KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(256).build(),
        )
        return g.generateKey()
    }

    override fun protect(b: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key()) }
        return c.iv + c.doFinal(b)
    }

    override fun unprotect(b: ByteArray): ByteArray {
        val c = Cipher.getInstance("AES/GCM/NoPadding").apply {
            init(Cipher.DECRYPT_MODE, key(), GCMParameterSpec(128, b.copyOfRange(0, 12)))
        }
        return c.doFinal(b.copyOfRange(12, b.size))
    }
}

/** Registro de accesos denegados (archivo con cada intento cifrado con la clave pública). */
class DeniedLog(private val file: File, private val pending: Pending? = null) {
    @Synchronized
    private fun load(): MutableList<JSONObject> = try {
        if (!file.exists()) mutableListOf()
        else JSONArray(file.readText()).let { a -> (0 until a.length()).map { a.getJSONObject(it) }.toMutableList() }
    } catch (e: Exception) {
        mutableListOf()
    }

    @Synchronized
    private fun save(items: List<JSONObject>) {
        val tmp = File(file.path + ".tmp")
        tmp.writeText(JSONArray(items.takeLast(DENIED_MAX)).toString())
        if (!tmp.renameTo(file)) { file.delete(); tmp.renameTo(file) }
    }

    private fun entry(id: String, time: String, pub: String, p: JSONObject): JSONObject = JSONObject().apply {
        put("id", id); put("t", time); put("rev", nowRev()) // rev: para fusionar con el PC
        if (pub.isNotEmpty()) put("blob", Seal.seal(pub, p.toString()))
        else if (pending != null) {
            // aún no hay clave del registro: se protege con el Keystore y se sella en el primer desbloqueo (migrate)
            try { put("dp", b64(pending.protect(p.toString().toByteArray(Charsets.UTF_8)))) }
            catch (e: Exception) { put("plain", JSONObject(p.toString()).put("pw", JSONObject.NULL)) }
        } else put("plain", JSONObject(p.toString()).put("pw", JSONObject.NULL)) // sin protección: no se guarda la contraseña
    }

    /** Pasa a la caja sellada los intentos que se protegieron antes de que existiera la clave. */
    fun migrate(pub: String) {
        val p = pending ?: return
        synchronized(this) {
            val items = load()
            var changed = false
            for (e in items) {
                if (!e.has("dp")) continue
                try {
                    val payload = String(p.unprotect(unb64(e.getString("dp"))), Charsets.UTF_8)
                    e.remove("dp"); e.put("blob", Seal.seal(pub, payload)); e.put("rev", nowRev()); changed = true
                } catch (ex: Exception) { /* se deja como está */ }
            }
            if (changed) save(items)
        }
    }

    /**
     * Anota el intento ahora y completa IP/ubicación cuando `geo` responde. Llamar desde un hilo de fondo.
     */
    fun record(pub: String, password: String, device: String, lan: String, geo: () -> Pair<String, String>): String {
        val id = java.util.UUID.randomUUID().toString().replace("-", "")
        val time = nowIso()
        val base = JSONObject().put("pw", password).put("ip", "").put("lan", lan).put("loc", "").put("dev", device)
        synchronized(this) { save(load().apply { add(entry(id, time, pub, base)) }) }
        val (ip, loc) = try { geo() } catch (e: Exception) { "" to "" }
        synchronized(this) {
            val items = load()
            val i = items.indexOfFirst { it.optString("id") == id }
            if (i >= 0) {
                items[i] = entry(id, time, pub, JSONObject(base.toString()).put("ip", ip).put("loc", loc))
                save(items)
            }
        }
        return id
    }

    /** Intentos ya cifrados (los únicos que se comparten con el PC), los más recientes primero. */
    fun synced(limit: Int = 50): JSONArray = JSONArray(
        load().filter { it.has("blob") }.takeLast(limit).map {
            JSONObject().put("id", it.optString("id")).put("t", it.optString("t"))
                .put("blob", it.optString("blob")).put("rev", it.optString("rev"))
        },
    )

    /** Incorpora los intentos del otro dispositivo (gana la revisión más reciente) y aplica los borrados. */
    fun mergeIn(remote: List<JSONObject>, deleted: Map<String, String>): Int = synchronized(this) {
        val items = load()
        val mine = LinkedHashMap<String, JSONObject>()
        items.filter { it.has("blob") }.forEach { mine[it.optString("id")] = it }
        var added = 0
        for (r in remote) {
            val id = r.optString("id"); val blob = r.optString("blob")
            if (id.isEmpty() || id.length > 64 || blob.isEmpty() || blob.length > 4096) continue
            val rev = r.optString("rev").take(40)
            if (deleted[id]?.let { it >= rev } == true) continue
            val cur = mine[id]
            if (cur == null) {
                added++
                mine[id] = JSONObject().put("id", id).put("t", r.optString("t").take(40)).put("blob", blob).put("rev", rev)
            } else if (rev > cur.optString("rev")) {
                mine[id] = JSONObject().put("id", id).put("t", cur.optString("t")).put("blob", blob).put("rev", rev)
            }
        }
        val kept = mine.values.filter { e -> deleted[e.optString("id")].let { it == null || e.optString("rev") > it } }
        save(items.filter { !it.has("blob") } + kept.sortedBy { it.optString("t") })
        added
    }

    /** Al adoptar la clave del PC: vuelve a sellar con ella los intentos propios (los del PC ya la usan). */
    fun reseal(oldPriv: String, newPub: String) = synchronized(this) {
        val items = load()
        var changed = false
        for (e in items) {
            if (!e.has("blob")) continue
            try {
                e.put("blob", Seal.seal(newPub, Seal.unseal(oldPriv, e.getString("blob"))))
                e.put("rev", nowRev()); changed = true
            } catch (ex: Exception) { /* sellado con otra clave: se deja */ }
        }
        if (changed) save(items)
    }

    fun ids(): List<String> = load().map { it.optString("id") }

    fun read(privB64: String): List<DeniedRow> = load().map { e ->
        val p: JSONObject? = try {
            when {
                e.has("blob") -> JSONObject(Seal.unseal(privB64, e.getString("blob")))
                e.has("dp") && pending != null -> JSONObject(String(pending.unprotect(unb64(e.getString("dp"))), Charsets.UTF_8))
                else -> e.optJSONObject("plain")
            }
        } catch (ex: Exception) {
            null
        }
        DeniedRow(
            e.optString("id"), e.optString("t"),
            if (p == null || p.isNull("pw")) null else p.optString("pw"),
            p?.optString("ip") ?: "", p?.optString("lan") ?: "", p?.optString("loc") ?: "",
            p?.optString("dev") ?: "(no se puede descifrar)",
        )
    }.reversed().sortedByDescending { it.time }

    fun unseen(seenIso: String): Int = load().count { it.optString("t") > seenIso }

    fun clear() = save(emptyList())
}

fun lanIp(): String = try {
    NetworkInterface.getNetworkInterfaces().toList().flatMap { it.inetAddresses.toList() }
        .firstOrNull { !it.isLoopbackAddress && it.isSiteLocalAddress && it.address.size == 4 }?.hostAddress ?: ""
} catch (e: Exception) {
    ""
}

/** IP pública y ubicación aproximada (servicio ipwho.is). Sin conexión devuelve vacío. */
fun geoLookup(): Pair<String, String> = try {
    val c = URL("https://ipwho.is/").openConnection() as HttpURLConnection
    c.connectTimeout = 6000; c.readTimeout = 6000
    val j = JSONObject(c.inputStream.use { it.readBytes().toString(Charsets.UTF_8) })
    if (j.optBoolean("success")) {
        j.optString("ip") to listOf(j.optString("city"), j.optString("region"), j.optString("country"))
            .filter { it.isNotBlank() }.joinToString(", ")
    } else "" to ""
} catch (e: Exception) {
    "" to ""
}
