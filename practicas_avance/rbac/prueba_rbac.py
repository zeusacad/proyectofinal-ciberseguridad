from pathlib import Path
import sqlite3, secrets, hashlib, hmac, csv
base=Path.home()/"Desktop/ZERO-DAY-LAB"
folder=base/"rbac"
folder.mkdir(parents=True, exist_ok=True)
db=folder/"laboratorio.sqlite"
con=sqlite3.connect(db)
con.execute("CREATE TABLE IF NOT EXISTS cuentas (usuario TEXT PRIMARY KEY, perfil TEXT NOT NULL, salt BLOB NOT NULL, hash BLOB NOT NULL)")
con.execute("CREATE TABLE IF NOT EXISTS autorizaciones (perfil TEXT, permiso TEXT, PRIMARY KEY (perfil, permiso))")
roles={"admin_demo":"administrador", "operador_demo":"operador", "auditor_demo":"auditor"}
permisos={"administrador":{"usuarios:consultar"}, "operador":{"expedientes:editar"}, "auditor":{"auditoria:consultar"}}
claves={}
for usuario, perfil in roles.items():
    clave=secrets.token_urlsafe(30)
    salt=secrets.token_bytes(16)
    digest=hashlib.pbkdf2_hmac('sha256', clave.encode(), salt, 250_000)
    con.execute("INSERT OR REPLACE INTO cuentas VALUES (?,?,?,?)", (usuario,perfil,salt,digest))
    claves[usuario]=clave # solo en memoria; no se registra en archivos
con.execute("DELETE FROM autorizaciones")
for perfil, acciones in permisos.items():
    for accion in acciones:
        con.execute("INSERT INTO autorizaciones VALUES (?,?)", (perfil,accion))
con.commit()
pruebas=[("admin_demo","usuarios:consultar",True),("admin_demo","claves:consultar",False),
         ("operador_demo","expedientes:editar",True),("operador_demo","usuarios:consultar",False),
         ("auditor_demo","auditoria:consultar",True),("auditor_demo","expedientes:editar",False)]
resultados=[]
for usuario, accion, esperado in pruebas:
    perfil,salt,digest=con.execute("SELECT perfil,salt,hash FROM cuentas WHERE usuario=?",(usuario,)).fetchone()
    autenticado=hmac.compare_digest(hashlib.pbkdf2_hmac('sha256',claves[usuario].encode(),salt,250_000),digest)
    autorizado=con.execute("SELECT 1 FROM autorizaciones WHERE perfil=? AND permiso=?",(perfil,accion)).fetchone() is not None
    permitido=autenticado and autorizado
    resultados.append((usuario,perfil,accion,"PERMITIDO" if permitido else "DENEGADO","OK" if permitido == esperado else "ERROR"))
con.close()
with (base/"evidencias/ZD03_pruebas_rbac.csv").open("w",newline="") as f:
    writer=csv.writer(f);writer.writerow(["usuario","perfil","accion","resultado","verificacion"]);writer.writerows(resultados)
with (base/"evidencias/ZD03_resumen_rbac.txt").open("w") as f:
    for r in resultados:f.write(" | ".join(r)+"\n")
    f.write(f"PRUEBAS CORRECTAS: {sum(r[-1]=='OK' for r in resultados)} de {len(resultados)}\n")
print("RBAC: ",sum(r[-1]=='OK' for r in resultados),"de",len(resultados),"pruebas correctas")
assert all(r[-1]=="OK" for r in resultados)
