"""Arranca el Gestor del PC (sincronización activa, datos de prueba) para las pruebas de integración del cliente Kotlin.
Uso: python sync_harness.py <archivo_enlace> <archivo_resultado> [segundos]"""
import json, os, sys, tempfile, time
sys.path.insert(0, r"C:\Users\b_o_y\Gestor de contrase" + "\xf1" + "as")
import gestor

link_file, result_file = sys.argv[1], sys.argv[2]
limit = int(sys.argv[3]) if len(sys.argv) > 3 else 240
tmp = tempfile.mkdtemp()
gestor.APP_DIR = tmp
gestor.VAULT = os.path.join(tmp, "b.dat")
a = gestor.App()
a.vault.create("clave-maestra")
a.vault.data["correos"] = [
    a.vault.new_entry({"user": "ana@x.com", "pass": "original", "created": gestor.now_iso()}),
    a.vault.new_entry({"user": "borrar@x.com", "pass": "bye", "created": gestor.now_iso()}),
    a.vault.new_entry({"user": "solo-pc@x.com", "pass": "pc", "created": gestor.now_iso()}),
]
a.vault.save()
a.cfg["sync_enabled"] = True
a.cfg["sync_port"] = 47955
a.sync_start()
assert a.sync_srv and a.sync_srv.running, a.sync_error
a.show_main()
# un intento fallido hecho en el PC: debe llegar al móvil
gestor.record_denied(a.cfg["deny_pub"], "Intento-en-el-PC", geo=lambda: {"ip": "9.9.9.9", "loc": "Valencia, España"}, wait=True)
link, _ = a.sync_new_pairing()
open(link_file, "w").write(link)
print("arnés listo en el puerto 47955", flush=True)
end = time.time() + limit
while time.time() < end:
    a.update()
    time.sleep(0.02)
    if os.path.exists(result_file + ".stop"):
        break
d = a.vault.data
json.dump({"correos": [(e["user"], e["pass"]) for e in d["correos"]], "webs": [(e["user"], e["pass"]) for e in d["webs"]],
           "tombstones": len(d["deleted"]), "denied": [(r["pw"], r["dev"], r["loc"]) for r in gestor.read_denied(d["denykey"])], "devices": [x["name"] for x in a.cfg["sync_devices"]]}, open(result_file, "w"))
a.sync_stop()
a.destroy()

