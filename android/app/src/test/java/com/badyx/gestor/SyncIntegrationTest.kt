package com.badyx.gestor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.File

/**
 * Prueba contra el Gestor real del PC. Solo se ejecuta si GESTOR_LINK_FILE apunta a un archivo con el
 * enlace de vinculación (lo crea sync_harness.py, que arranca el servidor del PC con datos de prueba).
 */
class SyncIntegrationTest {
    @Test
    fun fullCycleAgainstPc() {
        val path = System.getenv("GESTOR_LINK_FILE") ?: return
        val link = Sync.parseLink(File(path).readText().trim())

        // código malo -> rechazado sin revelar nada
        try {
            Sync.pair(PairLink(link.hosts, link.port, link.fingerprint, "0000000000"), "x"); fail("debía rechazar")
        } catch (e: SyncException) {
            assertEquals(SyncException.Kind.CODE, e.kind)
        }

        val p = Sync.pair(link, "Prueba Kotlin")
        // el certificado se fija por huella: con otra huella la conexión se rechaza
        try {
            Sync.sync(Pairing(p.hosts, p.port, "00".repeat(32), p.deviceId, p.secret, p.lastHost), null); fail("debía rechazar")
        } catch (e: SyncException) {
            assertEquals(SyncException.Kind.NETWORK, e.kind)
        }
        // credenciales falsas
        try {
            Sync.sync(Pairing(p.hosts, p.port, p.fingerprint, p.deviceId, "falso", p.lastHost), null); fail("debía rechazar")
        } catch (e: SyncException) {
            assertEquals(SyncException.Kind.AUTH, e.kind)
        }

        // descarga y descifrado con la contraseña maestra del PC
        val blob = Sync.sync(p, null)
        val salt = Crypto.saltOf(blob)
        val key = Crypto.deriveKey("clave-maestra", salt)
        val data = VaultData.fromJson(Crypto.unpack(key, blob))
        assertTrue(data.correos.any { it.user == "ana@x.com" })

        // el móvil edita, añade y borra
        data.correos.first { it.user == "ana@x.com" }.let { it.pass = "editada-desde-kotlin"; it.rev = nowRev() }
        data.webs.add(Entry.create("https://kotlin.test", "k-pass", "yo", "nota"))
        val victim = data.correos.first { it.user == "borrar@x.com" }
        data.deleted[victim.id] = nowRev()
        data.correos.remove(victim)
        val reply = Sync.sync(p, Crypto.pack(key, salt, data.toJson().toString()))
        val merged = VaultData.fromJson(Crypto.unpack(key, reply))

        // y recibe lo que el PC cambió mientras tanto (la entrada «solo-pc» la crea el arnés antes de sincronizar)
        assertTrue(merged.webs.any { it.user == "https://kotlin.test" })
        assertFalse(merged.correos.any { it.user == "borrar@x.com" })
        assertEquals("editada-desde-kotlin", merged.correos.first { it.user == "ana@x.com" }.pass)
        assertTrue(merged.correos.any { it.user == "solo-pc@x.com" })
    }
}
