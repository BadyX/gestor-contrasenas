package com.badyx.gestor

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.provider.Settings
import androidx.core.content.FileProvider
import org.json.JSONObject
import java.io.File
import java.net.HttpURLConnection
import java.net.URL
import java.security.MessageDigest

/** Datos de la versión publicada (android.json de la release «android» del repositorio). */
data class UpdateInfo(
    val versionName: String, val versionCode: Int, val file: String,
    val sha256: String, val size: Long, val notes: List<String>,
)

/**
 * Busca versiones nuevas en GitHub y las instala con el instalador de Android. La seguridad no depende solo
 * de este manifiesto: Android rechaza cualquier APK que no esté firmado con la misma clave que la app instalada.
 * Además se comprueban el tamaño y el SHA-256.
 */
object Updater {
    const val BASE = "https://github.com/BadyX/gestor-contrasenas/releases/download/android/"
    private const val MAX_BYTES = 100L * 1024 * 1024
    private val FILE_RE = Regex("^[A-Za-z0-9._-]{1,80}\\.apk$")

    fun parse(text: String): UpdateInfo {
        val j = JSONObject(text)
        val notes = j.optJSONArray("notes")
        return UpdateInfo(
            j.getString("version"), j.getInt("versionCode"), j.getString("file"),
            j.getString("sha256").lowercase(), j.getLong("size"),
            (0 until (notes?.length() ?: 0)).map { notes!!.getString(it) },
        )
    }

    private fun open(url: String): HttpURLConnection = (URL(url).openConnection() as HttpURLConnection).apply {
        connectTimeout = 10_000; readTimeout = 30_000; instanceFollowRedirects = true
        setRequestProperty("User-Agent", "GestorMovil/${BuildConfig.VERSION_NAME}")
    }

    /** La versión nueva si la publicada es más reciente que la instalada; null si no hay nada que actualizar. */
    fun check(current: Int = BuildConfig.VERSION_CODE): UpdateInfo? {
        val c = open(BASE + "android.json")
        try {
            if (c.responseCode != 200) throw java.io.IOException("HTTP ${c.responseCode}")
            val info = parse(c.inputStream.use { it.readBytes().decodeToString() })
            return if (info.versionCode > current && FILE_RE.matches(info.file) && info.size in 1..MAX_BYTES) info else null
        } finally { c.disconnect() }
    }

    /** Descarga el APK a la caché y comprueba tamaño y SHA-256. */
    fun download(ctx: Context, info: UpdateInfo): File {
        val dir = File(ctx.cacheDir, "updates").apply { mkdirs(); listFiles()?.forEach { it.delete() } }
        val dest = File(dir, info.file)
        val md = MessageDigest.getInstance("SHA-256")
        val c = open(BASE + info.file)
        try {
            if (c.responseCode != 200) throw java.io.IOException("HTTP ${c.responseCode}")
            var total = 0L
            c.inputStream.use { input ->
                dest.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        total += n
                        if (total > MAX_BYTES) throw java.io.IOException("Archivo demasiado grande")
                        md.update(buf, 0, n); out.write(buf, 0, n)
                    }
                }
            }
            val hex = md.digest().joinToString("") { "%02x".format(it) }
            if (total != info.size || hex != info.sha256) { dest.delete(); throw java.io.IOException("La descarga no coincide con lo publicado") }
            return dest
        } finally { c.disconnect() }
    }

    fun canInstall(ctx: Context) = ctx.packageManager.canRequestPackageInstalls()

    /** Abre los ajustes para permitir que la app instale APK (solo hace falta la primera vez). */
    fun askPermission(ctx: Context) {
        ctx.startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${ctx.packageName}"))
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    fun install(ctx: Context, apk: File) {
        val uri = FileProvider.getUriForFile(ctx, "${ctx.packageName}.files", apk)
        ctx.startActivity(Intent(Intent.ACTION_VIEW).setDataAndType(uri, "application/vnd.android.package-archive")
            .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK or Intent.FLAG_GRANT_READ_URI_PERMISSION))
    }
}
