package com.badyx.gestor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File

class SecurityTest {
    private class MapKV : KV {
        val m = mutableMapOf<String, String>()
        override fun getString(k: String) = m[k]
        override fun putString(k: String, v: String) { m[k] = v }
    }

    @Test
    fun lockDurationsMatchSpec() {
        assertEquals(listOf(600L, 86_400L, 172_800L, 259_200L), (1..4).map { LockGuard.lockSeconds(it) })
        assertEquals("10 min 00 s", LockGuard.format(600))
        assertEquals("1 día 0 h 00 min 00 s", LockGuard.format(86_400))
        assertEquals("2 días 3 h 04 min 05 s", LockGuard.format(2 * 86_400 + 3 * 3600 + 4 * 60 + 5))
    }

    @Test
    fun twoWrongAttemptsLockAndEscalate() {
        val g = LockGuard(MapKV())
        assertEquals(2, g.attemptsLeft())
        assertEquals(0L, g.registerFailure(1000.0))
        assertEquals(1, g.attemptsLeft())
        assertEquals(600L, g.registerFailure(1001.0))                // 1.er bloqueo: 10 min
        assertEquals(2, g.attemptsLeft())
        assertEquals(599L, g.remaining(1002.0))
        assertEquals(0L, g.remaining(1001.0 + 600))                  // vence a los 10 min
        g.registerFailure(2000.0)
        assertEquals(86_400L, g.registerFailure(2001.0))             // 2.º: 1 día
        g.registerFailure(200_000.0)
        assertEquals(172_800L, g.registerFailure(200_001.0))         // 3.º: 2 días
        g.registerSuccess()
        assertEquals(0L, g.remaining(200_002.0))
        g.registerFailure(300_000.0)
        assertEquals(600L, g.registerFailure(300_001.0))             // tras acertar se reinicia: vuelve a 10 min
    }

    @Test
    fun movingTheClockBackDoesNotShortenTheLock() {
        val g = LockGuard(MapKV())
        g.registerFailure(1000.0); g.registerFailure(1001.0)
        assertEquals(599L, g.remaining(1002.0))
        assertEquals(599L, g.remaining(1002.0 - 86_400))             // reloj atrasado 1 día: sigue igual
    }

    @Test
    fun decryptsSealedBoxCreatedByPc() {
        // Generado por la versión de PC (Python)
        val priv = "GNQ6rlWlL+QS5lSbxrVwbckGiXcnutHaejoMqpij+FQ="
        val pub = "Aksn1WcaZ5Y2yza3IdvxdHETa9+lH4U5v2drqf0bdAI="
        val blob = "0vX10qLmYf77DbUKomXu2P8XHlmqwenccBCJiTloY1bJpSCevBgdPw1ayCD0+H4IjqOxKAgne5f48/G51/iyEIyRfE1ehDYLOy/jJ3yTcu7j9mp771eXWrrmUzng/+9fVrvKmvhTaGpx9vwtRCgNadWwKEowQvN8574ND6W9zb6ojbaw9kc+OTioINIwtr8jvUgoaw=="
        assertEquals(pub, Seal.pubOf(priv))
        val p = org.json.JSONObject(Seal.unseal(priv, blob))
        assertEquals("Contr4señaMal", p.getString("pw"))
        assertEquals("Canals, España", p.getString("loc"))
    }

    @Test
    fun sealRoundTripAndWrongKey() {
        val (priv, pub) = Seal.keypair()
        val blob = Seal.seal(pub, """{"pw":"abc"}""")
        assertEquals("""{"pw":"abc"}""", Seal.unseal(priv, blob))
        val (other, _) = Seal.keypair()
        try { Seal.unseal(other, blob); throw AssertionError("otra clave no debía abrirlo") } catch (e: java.security.GeneralSecurityException) { }
        // para que el PC (Python) compruebe que descifra lo sellado en Kotlin
        File("build").mkdirs()
        File("build/kotlin-seal.txt").writeText(priv + "\n" + Seal.seal(pub, """{"pw":"Desde-Kotlin-ñ","dev":"Móvil"}"""))
    }

    /** Protección de prueba (en el móvil es el Keystore): AES-GCM con una clave en memoria. */
    private class FakePending : Pending {
        private val k = javax.crypto.spec.SecretKeySpec(ByteArray(16) { it.toByte() }, "AES")
        override fun protect(b: ByteArray): ByteArray {
            val c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").apply { init(javax.crypto.Cipher.ENCRYPT_MODE, k) }
            return c.iv + c.doFinal(b)
        }
        override fun unprotect(b: ByteArray): ByteArray {
            val c = javax.crypto.Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(javax.crypto.Cipher.DECRYPT_MODE, k, javax.crypto.spec.GCMParameterSpec(128, b.copyOfRange(0, 12)))
            }
            return c.doFinal(b.copyOfRange(12, b.size))
        }
    }

    @Test
    fun attemptsBeforeTheKeyExistKeepTheirPasswordAfterMigration() {
        val f = File.createTempFile("denied2", ".json"); f.deleteOnExit()
        val log = DeniedLog(f, FakePending())
        log.record("", "Fallo-antes-de-la-clave", "Móvil", "10.0.0.2") { "1.2.3.4" to "Madrid, España" }
        assertFalse("Fallo-antes" in f.readText() || "1.2.3.4" in f.readText())   // protegido, no en claro
        val (priv, pub) = Seal.keypair()
        assertEquals("Fallo-antes-de-la-clave", log.read(priv).first().password)    // legible aun sin migrar
        log.migrate(pub)
        assertTrue(f.readText().contains("blob") && !f.readText().contains("\"dp\""))
        val r = log.read(priv).first()
        assertEquals("Fallo-antes-de-la-clave", r.password); assertEquals("Madrid, España", r.location)
    }

    @Test
    fun deniedEntriesMergeWithTombstonesAndNewestRevisionWins() {
        val (priv, pub) = Seal.keypair()
        val f = File.createTempFile("denied3", ".json"); f.deleteOnExit()
        val log = DeniedLog(f)
        fun e(id: String, rev: String, pw: String, t: String = "2026-10-26T12:00:00") = org.json.JSONObject()
            .put("id", id).put("t", t).put("rev", rev).put("blob", Seal.seal(pub, """{"pw":"$pw","dev":"PC"}"""))
        val r1 = "2026-10-26T10:00:00.000+00:00"; val r2 = "2026-10-26T10:05:00.000+00:00"
        assertEquals(2, log.mergeIn(listOf(e("a", r1, "viejo"), e("b", r1, "otro")), emptyMap()))
        assertEquals(0, log.mergeIn(listOf(e("a", r2, "nuevo")), emptyMap()))            // misma id: no es nueva
        assertEquals(setOf("nuevo", "otro"), log.read(priv).map { it.password }.toSet())  // gana la revisión más reciente
        log.mergeIn(listOf(e("a", r1, "viejo-de-nuevo")), emptyMap())                    // revisión antigua: se ignora
        assertTrue(log.read(priv).any { it.password == "nuevo" })
        log.mergeIn(emptyList(), mapOf("a" to r2))                                       // lápida igual o más reciente: se borra
        assertEquals(listOf("otro"), log.read(priv).map { it.password })
        assertEquals(0, log.mergeIn(listOf(e("a", r2, "resucita")), mapOf("a" to r2)))   // y no reaparece
        assertEquals(listOf("otro"), log.read(priv).map { it.password })
        assertEquals(1, log.synced().length())
    }

    @Test
    fun adoptingThePcKeyResealsOwnAttemptsSoBothCanRead() {
        val (oldPriv, oldPub) = Seal.keypair()
        val (pcPriv, pcPub) = Seal.keypair()
        val f = File.createTempFile("denied4", ".json"); f.deleteOnExit()
        val log = DeniedLog(f)
        log.record(oldPub, "intento-propio", "Móvil", "10.0.0.2") { "1.1.1.1" to "Madrid" }
        assertTrue(log.read(pcPriv).first().password == null)             // el PC aún no puede leerlo
        log.reseal(oldPriv, pcPub)
        assertEquals("intento-propio", log.read(pcPriv).first().password) // ahora sí
        assertTrue(log.read(oldPriv).first().password == null)
    }

    @Test
    fun deniedLogStoresEncryptedAndFillsLocationLater() {
        val f = File.createTempFile("denied", ".json"); f.deleteOnExit()
        val log = DeniedLog(f)
        val (priv, pub) = Seal.keypair()
        log.record(pub, "mala-clave-1", "Móvil · Test", "192.168.1.5") { "1.2.3.4" to "Madrid, España" }
        log.record(pub, "mala-clave-2", "Móvil · Test", "192.168.1.5") { "" to "" }
        val raw = f.readText()
        assertFalse("mala-clave" in raw || "1.2.3.4" in raw || "Madrid" in raw)   // nada en claro en disco
        val rows = log.read(priv)
        assertEquals(listOf("mala-clave-2", "mala-clave-1"), rows.map { it.password })  // más reciente primero
        assertEquals("1.2.3.4", rows[1].ip); assertEquals("Madrid, España", rows[1].location)
        assertEquals("Móvil · Test", rows[0].device)
        assertEquals(2, log.unseen("")); assertEquals(0, log.unseen("9999"))
        // sin clave pública: la contraseña no se guarda
        log.record("", "secreta", "d", "") { "" to "" }
        assertNull(log.read(priv).first().password)
        log.clear(); assertTrue(log.read(priv).isEmpty())
    }
}
