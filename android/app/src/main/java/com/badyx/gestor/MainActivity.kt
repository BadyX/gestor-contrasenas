package com.badyx.gestor

import android.content.Intent
import android.os.Bundle
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.viewModels
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions

class MainActivity : ComponentActivity() {
    private val vm: AppViewModel by viewModels()

    private val scanner = registerForActivityResult(ScanContract()) { result ->
        result.contents?.let { vm.pendingLink = it }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        // sin capturas de pantalla ni vista previa en «recientes»: la app muestra contraseñas
        if (!BuildConfig.DEBUG) { // en la versión de pruebas se permiten capturas para verificar la interfaz
            window.setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE)
        }
        handleIntent(intent)
        setContent {
            GestorTheme {
                Root(vm, onScan = {
                    scanner.launch(
                        ScanOptions().setPrompt("Escanea el QR que muestra el Gestor del PC")
                            .setBeepEnabled(false).setOrientationLocked(false)
                            .setDesiredBarcodeFormats(ScanOptions.QR_CODE),
                    )
                })
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    private fun handleIntent(i: Intent?) {
        val d = i?.dataString
        if (d != null && d.startsWith("gestor://")) vm.pendingLink = d // enlace de vinculación recibido por mensaje
    }

    override fun onStart() {
        super.onStart()
        vm.onForeground()
    }

    override fun onStop() {
        super.onStop()
        vm.onBackground()
    }
}
