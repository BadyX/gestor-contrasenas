package com.badyx.gestor

import java.io.File
import java.security.SecureRandom

/** Archivo cifrado del móvil (mismo formato que el del PC). Escritura atómica: nunca queda a medias. */
class VaultFile(private val file: File) {
    fun exists() = file.exists()
    fun read(): ByteArray = file.readBytes()

    fun write(blob: ByteArray) {
        val tmp = File(file.path + ".tmp")
        tmp.writeBytes(blob)
        if (!tmp.renameTo(file)) {
            file.delete()
            tmp.renameTo(file)
        }
    }

    fun delete() {
        file.delete()
    }
}

private const val LOWER = "abcdefghijklmnopqrstuvwxyz"
private const val UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
private const val DIGITS = "0123456789"
private const val SYMBOLS = "!@#$%&*?-_+="

/** Contraseña aleatoria con minúsculas, mayúsculas, números y símbolos. */
fun generatePassword(length: Int = 16): String {
    val rnd = SecureRandom()
    val pools = listOf(LOWER, UPPER, DIGITS, SYMBOLS)
    val all = pools.joinToString("")
    val chars = pools.map { it[rnd.nextInt(it.length)] }.toMutableList()
    repeat(length - chars.size) { chars.add(all[rnd.nextInt(all.length)]) }
    chars.shuffle(rnd)
    return chars.joinToString("")
}

/** Nivel 0..4 de fortaleza (mismas reglas que el PC). */
fun strength(pw: String): Int {
    if (pw.isEmpty()) return 0
    val classes = listOf(pw.any { it.isLowerCase() }, pw.any { it.isUpperCase() },
        pw.any { it.isDigit() }, pw.any { !it.isLetterOrDigit() }).count { it }
    var pts = (if (pw.length >= 8) 1 else 0) + (if (pw.length >= 12) 1 else 0) +
        (if (pw.length >= 16) 1 else 0) + (if (classes >= 3) 1 else 0)
    if (pw.toSet().size <= 3 || pw.length < 6) pts = 0
    return maxOf(1, pts)
}
