package com.badyx.gestor

import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.net.URL
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.cert.CertificateException
import java.security.cert.X509Certificate
import java.util.Base64
import javax.net.ssl.HostnameVerifier
import javax.net.ssl.HttpsURLConnection
import javax.net.ssl.SSLContext
import javax.net.ssl.SSLSocketFactory
import javax.net.ssl.X509TrustManager

/** Datos del QR que muestra el PC. */
class PairLink(val hosts: List<String>, val port: Int, val fingerprint: String, val code: String)

/** Lo que el móvil recuerda del PC vinculado. */
class Pairing(
    val hosts: List<String>, val port: Int, val fingerprint: String,
    val deviceId: String, val secret: String, var lastHost: String,
) {
    fun toJson() = JSONObject().apply {
        put("hosts", JSONArray(hosts)); put("port", port); put("fp", fingerprint)
        put("id", deviceId); put("secret", secret); put("last", lastHost)
    }

    companion object {
        fun fromJson(j: JSONObject) = Pairing(
            (0 until j.getJSONArray("hosts").length()).map { j.getJSONArray("hosts").getString(it) },
            j.getInt("port"), j.getString("fp"), j.getString("id"), j.getString("secret"), j.optString("last"),
        )
    }
}

class SyncException(val kind: Kind, message: String) : Exception(message) {
    enum class Kind { LOCKED, KEY, AUTH, CODE, NETWORK, OTHER }
}

class PairingStore(private val file: File) {
    fun load(): Pairing? = try {
        if (file.exists()) Pairing.fromJson(JSONObject(file.readText())) else null
    } catch (e: Exception) {
        null
    }

    fun save(p: Pairing) {
        file.writeText(p.toJson().toString())
    }

    fun clear() {
        file.delete()
    }
}

/**
 * Cliente de sincronización con el PC. La conexión es HTTPS contra un certificado autofirmado que se
 * reconoce por su huella SHA-256 (viene en el QR): no se usa ninguna autoridad de certificación.
 */
object Sync {
    fun parseLink(text: String): PairLink {
        val t = text.trim()
        val raw = if (t.startsWith("gestor://")) {
            val d = t.substringAfter("d=", "").substringBefore("&")
            String(Base64.getUrlDecoder().decode(d), Charsets.UTF_8)
        } else t
        return try {
            val j = JSONObject(raw)
            val h = j.getJSONArray("h")
            PairLink((0 until h.length()).map { h.getString(it) }, j.getInt("p"), j.getString("f"), j.getString("c"))
        } catch (e: Exception) {
            throw SyncException(SyncException.Kind.OTHER, "El enlace o QR de vinculación no es válido")
        }
    }

    private fun pinned(fp: String): SSLSocketFactory {
        val tm = object : X509TrustManager {
            override fun checkClientTrusted(chain: Array<X509Certificate>, authType: String) {}
            override fun checkServerTrusted(chain: Array<X509Certificate>, authType: String) {
                val h = MessageDigest.getInstance("SHA-256").digest(chain[0].encoded)
                    .joinToString("") { "%02x".format(it) }
                if (!h.equals(fp, ignoreCase = true)) throw CertificateException("La huella del certificado no coincide")
            }

            override fun getAcceptedIssuers(): Array<X509Certificate> = arrayOf()
        }
        return SSLContext.getInstance("TLS").apply { init(null, arrayOf(tm), SecureRandom()) }.socketFactory
    }

    /** POST JSON; devuelve (código HTTP, cuerpo JSON). Lanza SyncException(NETWORK) si no hay conexión. */
    private fun post(host: String, port: Int, fp: String, path: String, body: JSONObject, bearer: String?): Pair<Int, JSONObject> {
        val conn = try {
            (URL("https://$host:$port$path").openConnection() as HttpsURLConnection).apply {
                sslSocketFactory = pinned(fp)
                hostnameVerifier = HostnameVerifier { _, _ -> true } // seguro: ya se fija el certificado exacto
                connectTimeout = 3000
                readTimeout = 30000
                requestMethod = "POST"
                doOutput = true
                setRequestProperty("Content-Type", "application/json")
                if (bearer != null) setRequestProperty("Authorization", "Bearer $bearer")
            }
        } catch (e: Exception) {
            throw SyncException(SyncException.Kind.NETWORK, e.message ?: "Sin conexión")
        }
        try {
            conn.outputStream.use { it.write(body.toString().toByteArray()) }
            val code = conn.responseCode
            val stream = if (code >= 400) conn.errorStream else conn.inputStream
            val text = stream?.use { it.readBytes().toString(Charsets.UTF_8) } ?: "{}"
            return code to (try { JSONObject(text) } catch (e: Exception) { JSONObject() })
        } catch (e: Exception) {
            throw SyncException(SyncException.Kind.NETWORK, e.message ?: "Sin conexión")
        } finally {
            conn.disconnect()
        }
    }

    /** Canjea el código del QR por las credenciales de este móvil. Prueba cada IP del PC. */
    fun pair(link: PairLink, deviceName: String): Pairing {
        var last: SyncException? = null
        for (host in link.hosts) {
            try {
                val (code, json) = post(host, link.port, link.fingerprint, "/pair",
                    JSONObject().put("code", link.code).put("name", deviceName), null)
                if (code == 200) return Pairing(link.hosts, link.port, link.fingerprint,
                    json.getString("device_id"), json.getString("secret"), host)
                throw SyncException(SyncException.Kind.CODE, "El código de vinculación no es válido o ha caducado")
            } catch (e: SyncException) {
                if (e.kind == SyncException.Kind.CODE) throw e
                last = e
            }
        }
        throw last ?: SyncException(SyncException.Kind.NETWORK, "No se encuentra el PC en la red")
    }

    /**
     * Avisa al PC de intentos de acceso fallidos (ya cifrados con la clave pública) sin necesitar la contraseña
     * maestra: sirve aunque el móvil siga bloqueado. Si el PC no está al alcance, se enviarán en la próxima sincronización.
     */
    fun denied(p: Pairing, entries: JSONArray) {
        if (entries.length() == 0) return
        val body = JSONObject().put("entries", entries)
        for (host in (listOf(p.lastHost) + p.hosts.filter { it != p.lastHost }).filter { it.isNotBlank() }) {
            try {
                val (code, _) = post(host, p.port, p.fingerprint, "/denied", body, "${p.deviceId}.${p.secret}")
                if (code == 200) { p.lastHost = host; return }
                return
            } catch (e: SyncException) { /* probar otra IP */ }
        }
    }

    /** Envía `blob` (o null para solo descargar) y devuelve el paquete fusionado por el PC. */
    fun sync(p: Pairing, blob: ByteArray?): ByteArray {
        val body = JSONObject().put("blob", if (blob == null) JSONObject.NULL else Base64.getEncoder().encodeToString(blob))
        val order = listOf(p.lastHost) + p.hosts.filter { it != p.lastHost }
        var last: SyncException? = null
        for (host in order.filter { it.isNotBlank() }) {
            try {
                val (code, json) = post(host, p.port, p.fingerprint, "/sync", body, "${p.deviceId}.${p.secret}")
                when (code) {
                    200 -> { p.lastHost = host; return Base64.getDecoder().decode(json.getString("blob")) }
                    401 -> throw SyncException(SyncException.Kind.AUTH, "Este móvil ya no está vinculado con el PC")
                    409 -> throw SyncException(SyncException.Kind.KEY, "La contraseña maestra del PC ha cambiado: vuelve a vincular")
                    423 -> throw SyncException(SyncException.Kind.LOCKED, "El Gestor del PC está bloqueado: desbloquéalo")
                    else -> throw SyncException(SyncException.Kind.OTHER, "Error del PC ($code)")
                }
            } catch (e: SyncException) {
                if (e.kind != SyncException.Kind.NETWORK) throw e
                last = e
            }
        }
        throw last ?: SyncException(SyncException.Kind.NETWORK, "No se encuentra el PC en la red")
    }
}
