package com.badyx.gestor

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class UpdaterTest {
    @Test
    fun parsesManifest() {
        val i = Updater.parse("""{"version":"1.5","versionCode":6,"file":"GestorContrasenas-Android-1.5.apk","sha256":"ABCD","size":123,"notes":["a","b"]}""")
        assertEquals(6, i.versionCode)
        assertEquals("abcd", i.sha256)
        assertEquals(listOf("a", "b"), i.notes)
        assertTrue(i.file.endsWith(".apk"))
    }
}
