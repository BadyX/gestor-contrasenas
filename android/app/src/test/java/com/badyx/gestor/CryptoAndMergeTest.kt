package com.badyx.gestor

import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test
import java.io.File
import java.util.Base64

class CryptoAndMergeTest {
    // Paquete generado por la versión de PC (Python): contraseña "clave-maestra ñ€", sal = 0..15
    private val pcBlob = "R0NWMQABAgMEBQYHCAkKCwwNDg9nQUFBQUFCcTNxT0hnanRGdy0tbjNLU1Ftd0ZsdURrVk5rRXA5bUp0OXJWV2hpVWtEc0UxZ2lRb3RtRWxQX053OU9FQlg2Sl9SSDdaS2NEdUFpLTdfTU9vQ28xSy00VlllWXRrWVJ5WDRQemJjQXUyV3JndTQ0ZzZfNW5qVnpiSnpwZkhrRVFRdElkWHhRRHVnOEhmMlRUNXFWSWpVdm9NVXQ5ellVWUh1U0V0YmhzVC05OHZ3cjlabUYtTno4NXQtb2tOUlZqVFA4ckhSXy16MlcxUUcwdEdlSnpCbG1ENnN1eFN6RURmYnlHQWJsSWlvN0NLQWRYaWtpSXdCUXM2QVlBc1FBREpGb2NURkdJVkdtMTlMcHVMUlU4N3N3TG40Qm1KNDdNMjh1MThQcDJRSVY3allsRVpGT2ZXTWgwVVJZeDVrbXVRc2FoX3h1ZDRXYmZEMVZwNUQyeEtwMldnTU0wb2p4c3g2d1oyV1NCbGpZc01USU8tcWpTMHZwcnVOYVRJcXNNeTdnakM="

    @Test
    fun decryptsPackageCreatedByPc() {
        val blob = Base64.getDecoder().decode(pcBlob)
        val salt = Crypto.saltOf(blob)
        assertEquals((0..15).toList(), salt.map { it.toInt() })
        val key = Crypto.deriveKey("clave-maestra ñ€", salt)
        val data = VaultData.fromJson(Crypto.unpack(key, blob))
        assertEquals("ana@x.com", data.correos[0].user)
        assertEquals("Pásw0rd!", data.correos[0].pass)
        assertEquals("2026-10-26T11:00:00.000+00:00", data.deleted["z9"])
    }

    @Test(expected = Crypto.WrongKeyException::class)
    fun wrongPasswordIsRejected() {
        val blob = Base64.getDecoder().decode(pcBlob)
        Crypto.unpack(Crypto.deriveKey("otra", Crypto.saltOf(blob)), blob)
    }

    @Test(expected = Crypto.WrongKeyException::class)
    fun tamperedDataIsRejected() {
        val blob = Base64.getDecoder().decode(pcBlob)
        blob[blob.size - 40] = (blob[blob.size - 40].toInt() xor 1).toByte()
        Crypto.unpack(Crypto.deriveKey("clave-maestra ñ€", Crypto.saltOf(blob)), blob)
    }

    /** Escribe un paquete creado en Kotlin; un script de Python comprueba que el PC lo descifra. */
    @Test
    fun writesPackageForPcToVerify() {
        val salt = ByteArray(16) { (0x10 + it).toByte() }
        val key = Crypto.deriveKey("pw-kotlin ñ", salt)
        val entry = Entry.create("https://movil.com", "Cl@ve-ñ-1", "yo", "nota")
        val json = VaultData(webs = mutableListOf(entry)).toJson().toString()
        val blob = Crypto.pack(key, salt, json)
        assertEquals(json, Crypto.unpack(key, blob))
        File("build").mkdirs()
        File("build/kotlin-blob.txt").writeText(Base64.getEncoder().encodeToString(blob) + "\n" + entry.id)
    }

    private fun e(id: String, rev: String, pass: String = "x") =
        Entry(JSONObject().put("id", id).put("rev", rev).put("user", id).put("pass", pass))

    private fun t(n: Int) = "2026-10-26T10:00:%02d.000+00:00".format(n)

    @Test
    fun mergeNewestEditWinsAndDeletesPropagate() {
        val a = VaultData(mutableListOf(e("a", t(1), "viejo"), e("b", t(1)), e("c", t(1))), mutableListOf(e("w", t(1))))
        val b = VaultData(mutableListOf(e("a", t(5), "nuevo"), e("c", t(1)), e("d", t(3))), deleted = mutableMapOf("b" to t(4)))
        val m = mergeData(a, b)
        assertEquals(listOf("a", "c", "d"), m.correos.map { it.id }.sorted())
        assertEquals("nuevo", m.correos.first { it.id == "a" }.pass)
        assertEquals(listOf("w"), m.webs.map { it.id })
    }

    @Test
    fun mergeEditAfterDeleteSurvivesAndTieDeletes() {
        val survive = mergeData(VaultData(mutableListOf(e("x", t(9)))), VaultData(deleted = mutableMapOf("x" to t(2))))
        assertEquals(listOf("x"), survive.correos.map { it.id })
        val tie = mergeData(VaultData(mutableListOf(e("x", t(2)))), VaultData(deleted = mutableMapOf("x" to t(2))))
        assertTrue(tie.correos.isEmpty())
    }

    @Test
    fun mergeKeepsUndatedEntriesAndPrunesOldTombstones() {
        val m = mergeData(VaultData(mutableListOf(e("legacy", ""))), VaultData())
        assertEquals(listOf("legacy"), m.correos.map { it.id })
        val old = java.time.OffsetDateTime.now(java.time.ZoneOffset.UTC).minusDays(200).toString()
        val m2 = mergeData(VaultData(deleted = mutableMapOf("z" to old, "y" to nowRev())), VaultData())
        assertFalse("z" in m2.deleted)
        assertTrue("y" in m2.deleted)
    }

    @Test
    fun revisionFormatMatchesPc() {
        assertTrue(Regex("""\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}\+00:00""").matches(nowRev()))
    }
}
