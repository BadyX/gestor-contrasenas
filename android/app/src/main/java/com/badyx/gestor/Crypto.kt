package com.badyx.gestor

import org.bouncycastle.crypto.generators.SCrypt
import java.nio.ByteBuffer
import java.security.MessageDigest
import java.security.SecureRandom
import java.util.Base64
import javax.crypto.Cipher
import javax.crypto.Mac
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Cifrado idéntico al del PC: clave = scrypt(contraseña maestra, sal) y datos = Fernet
 * (AES-128-CBC + HMAC-SHA256). Un archivo/paquete es: "GCV1" + sal(16) + token Fernet.
 */
object Crypto {
    private val MAGIC = "GCV1".toByteArray(Charsets.US_ASCII)

    class WrongKeyException : Exception("Contraseña maestra incorrecta o datos de otro almacén")

    fun deriveKey(password: String, salt: ByteArray): ByteArray =
        SCrypt.generate(password.toByteArray(Charsets.UTF_8), salt, 32768, 8, 1, 32)

    fun newSalt(): ByteArray = ByteArray(16).also { SecureRandom().nextBytes(it) }

    fun fernetEncrypt(key: ByteArray, plain: ByteArray): ByteArray {
        val signing = key.copyOfRange(0, 16)
        val enc = key.copyOfRange(16, 32)
        val iv = ByteArray(16).also { SecureRandom().nextBytes(it) }
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(enc, "AES"), IvParameterSpec(iv))
        val ct = cipher.doFinal(plain)
        val ts = ByteBuffer.allocate(8).putLong(System.currentTimeMillis() / 1000).array()
        val body = byteArrayOf(0x80.toByte()) + ts + iv + ct
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(signing, "HmacSHA256")) }
        return Base64.getUrlEncoder().encode(body + mac.doFinal(body))
    }

    fun fernetDecrypt(key: ByteArray, token: ByteArray): ByteArray {
        val raw = try {
            Base64.getUrlDecoder().decode(token)
        } catch (e: IllegalArgumentException) {
            throw WrongKeyException()
        }
        if (raw.size < 1 + 8 + 16 + 16 + 32 || raw[0] != 0x80.toByte()) throw WrongKeyException()
        val signing = key.copyOfRange(0, 16)
        val enc = key.copyOfRange(16, 32)
        val body = raw.copyOfRange(0, raw.size - 32)
        val tag = raw.copyOfRange(raw.size - 32, raw.size)
        val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(signing, "HmacSHA256")) }
        if (!MessageDigest.isEqual(mac.doFinal(body), tag)) throw WrongKeyException()
        val iv = body.copyOfRange(9, 25)
        val ct = body.copyOfRange(25, body.size)
        val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(enc, "AES"), IvParameterSpec(iv))
        return try {
            cipher.doFinal(ct)
        } catch (e: Exception) {
            throw WrongKeyException()
        }
    }

    fun pack(key: ByteArray, salt: ByteArray, json: String): ByteArray =
        MAGIC + salt + fernetEncrypt(key, json.toByteArray(Charsets.UTF_8))

    fun saltOf(blob: ByteArray): ByteArray {
        if (blob.size < 21 || !blob.copyOfRange(0, 4).contentEquals(MAGIC)) throw WrongKeyException()
        return blob.copyOfRange(4, 20)
    }

    fun unpack(key: ByteArray, blob: ByteArray): String {
        saltOf(blob)
        return String(fernetDecrypt(key, blob.copyOfRange(20, blob.size)), Charsets.UTF_8)
    }
}
