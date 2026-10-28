package com.badyx.gestor

import org.json.JSONArray
import org.json.JSONObject
import java.time.LocalDateTime
import java.time.OffsetDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.util.UUID

/** Mismo formato que el PC: UTC con milisegundos, comparable como texto (p. ej. 2026-10-26T10:00:00.123+00:00). */
private val REV_FMT: DateTimeFormatter = DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSSxxx")
private val DATE_FMT: DateTimeFormatter = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm")

fun nowRev(): String = OffsetDateTime.now(ZoneOffset.UTC).format(REV_FMT)
fun nowIso(): String = LocalDateTime.now().withNano(0).toString()

fun formatDate(iso: String): String = try {
    LocalDateTime.parse(iso).format(DATE_FMT)
} catch (e: Exception) {
    ""
}

const val TOMBSTONE_DAYS = 180L

/** Una entrada. Se guarda el JSON tal cual para no perder campos que añada el PC en el futuro. */
class Entry(val json: JSONObject) {
    var id: String
        get() = json.optString("id")
        set(v) { json.put("id", v) }
    var user: String
        get() = json.optString("user")
        set(v) { json.put("user", v) }
    var pass: String
        get() = json.optString("pass")
        set(v) { json.put("pass", v) }
    var alias: String
        get() = json.optString("alias")
        set(v) { json.put("alias", v) }
    var notes: String
        get() = json.optString("notes")
        set(v) { json.put("notes", v) }
    val created: String get() = json.optString("created")
    val modified: String get() = json.optString("modified")
    var rev: String
        get() = json.optString("rev")
        set(v) { json.put("rev", v) }

    fun copy(): Entry = Entry(JSONObject(json.toString()))

    companion object {
        fun create(user: String, pass: String, alias: String, notes: String): Entry {
            val stamp = nowIso()
            return Entry(JSONObject().apply {
                put("id", UUID.randomUUID().toString().replace("-", ""))
                put("user", user); put("pass", pass); put("alias", alias); put("notes", notes)
                put("created", stamp); put("changed", stamp); put("rev", nowRev())
            })
        }
    }
}

/** Contenido del almacén: correos, webs y lápidas de lo borrado ({id: momento del borrado}). */
class VaultData(
    var correos: MutableList<Entry> = mutableListOf(),
    var webs: MutableList<Entry> = mutableListOf(),
    var deleted: MutableMap<String, String> = mutableMapOf(),
    private val extra: JSONObject = JSONObject(),
) {
    fun section(i: Int): MutableList<Entry> = if (i == 0) correos else webs

    /** Datos que solo viven en este móvil (p. ej. la clave privada del registro de accesos denegados). */
    fun extraString(key: String): String = extra.optString(key)
    fun extraPut(key: String, value: String) { extra.put(key, value) }

    fun extraArray(key: String): JSONArray? = extra.optJSONArray(key)

    /**
     * Lo que se comparte con el PC: correos, webs, lápidas y los intentos de acceso fallidos ya cifrados
     * (nunca otros datos locales ni la clave privada).
     */
    fun toSyncJson(denied: JSONArray? = null): JSONObject = JSONObject().apply {
        put("correos", JSONArray(correos.map { it.json }))
        put("webs", JSONArray(webs.map { it.json }))
        put("deleted", JSONObject(deleted as Map<*, *>))
        if (denied != null) put("denied", denied)
    }

    /** Todo lo que se guarda en el móvil. */
    fun toJson(): JSONObject = JSONObject(extra.toString()).apply {
        put("correos", JSONArray(correos.map { it.json }))
        put("webs", JSONArray(webs.map { it.json }))
        put("deleted", JSONObject(deleted as Map<*, *>))
    }

    fun copy(): VaultData = fromJson(toJson().toString())

    companion object {
        fun fromJson(text: String): VaultData {
            val j = JSONObject(text)
            fun list(key: String) = (0 until (j.optJSONArray(key)?.length() ?: 0))
                .map { Entry(j.getJSONArray(key).getJSONObject(it)) }.toMutableList()
            val del = mutableMapOf<String, String>()
            j.optJSONObject("deleted")?.let { o -> o.keys().forEach { del[it] = o.getString(it) } }
            val extra = JSONObject(text).apply { remove("correos"); remove("webs"); remove("deleted") }
            return VaultData(list("correos"), list("webs"), del, extra)
        }
    }
}

/**
 * Fusiona dos conjuntos con la misma regla que el PC: gana la revisión más reciente de cada id y un
 * borrado gana si es igual o más reciente que la entrada.
 */
fun mergeData(local: VaultData, remote: VaultData): VaultData {
    val deleted = local.deleted.toMutableMap()
    for ((id, r) in remote.deleted) if (r > (deleted[id] ?: "")) deleted[id] = r
    val limit = OffsetDateTime.now(ZoneOffset.UTC).minusDays(TOMBSTONE_DAYS).format(REV_FMT)
    deleted.entries.removeAll { it.value < limit }

    fun mergeSection(a: List<Entry>, b: List<Entry>): MutableList<Entry> {
        val best = LinkedHashMap<String, Entry>()
        for (e in a + b) {
            if (e.id.isBlank()) continue
            val cur = best[e.id]
            if (cur == null || e.rev > cur.rev) best[e.id] = e
        }
        return best.values.filter { it.id !in deleted || it.rev > deleted.getValue(it.id) }
            .map { it.copy() }.toMutableList()
    }
    return VaultData(
        mergeSection(local.correos, remote.correos),
        mergeSection(local.webs, remote.webs),
        deleted,
        JSONObject(local.toJson().toString()).apply { remove("correos"); remove("webs"); remove("deleted") },
    )
}
