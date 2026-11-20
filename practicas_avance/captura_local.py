import os, sys, time, shutil, subprocess, urllib.request, pathlib, socket
lab=pathlib.Path.home()/"Desktop/ZERO-DAY-LAB"
evid=lab/"evidencias"
port=8765
pcap=evid/"ZD05_Wireshark_loopback.pcapng"
info=evid/"ZD05_Wireshark_analisis.txt"
tshark=shutil.which("tshark")
if not tshark:
    info.write_text("PENDIENTE: tshark no disponible; no se genero captura.\n")
    print("Wireshark: tshark no disponible; pendiente")
    sys.exit(0)
with socket.socket() as s:
    try:s.bind(("127.0.0.1",port))
    except OSError:
        info.write_text("PENDIENTE: puerto 8765 ya ocupado; no se capturo.\n")
        print("Wireshark: puerto 8765 ocupado; no se abrió otro servidor")
        sys.exit(0)
server=None; capture=None
try:
    capture=subprocess.Popen([tshark,"-i","lo0","-f",f"tcp port {port}","-a","duration:10","-w",str(pcap)],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE,text=True)
    time.sleep(2)
    if capture.poll() is not None:
        raise RuntimeError("tshark no pudo iniciar la captura: "+capture.stderr.read()[-1000:])
    server=subprocess.Popen([sys.executable,"-m","http.server",str(port),"--bind","127.0.0.1","--directory",str(lab/"datos")],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    time.sleep(1)
    with urllib.request.urlopen(f"http://127.0.0.1:{port}/expedientes.csv",timeout=5) as response:
        body=response.read()
        status=response.status
    print(f"HTTP local GET: respuesta {status}, {len(body)} bytes")
    time.sleep(1)
finally:
    if server and server.poll() is None:
        server.terminate()
        try:server.wait(timeout=3)
        except subprocess.TimeoutExpired:server.kill();server.wait()
    if capture:
        try:capture.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            capture.terminate();capture.communicate(timeout=3)
# Analizar la captura ya cerrada; no inventar hallazgos.
if not pcap.exists() or pcap.stat().st_size < 100:
    info.write_text("PENDIENTE: no se obtuvo archivo pcapng util.\n")
    print("Wireshark: sin captura valida. Revisar permisos.")
    sys.exit(0)
analysis=subprocess.run([tshark,"-r",str(pcap),"-Y","http.request or http.response","-T","fields","-e","frame.number","-e","ip.src","-e","ip.dst","-e","http.request.method","-e","http.request.uri","-e","http.response.code"],capture_output=True,text=True)
with info.open("w") as f:
    f.write("CAPTURA REAL DE TRAFICO HTTP LOCAL (lo0, puerto 8765)\n")
    f.write("Origen de trafico: GET a expediente ficticio desde el mismo Mac\n")
    f.write("Consulta: http.request or http.response\n\n")
    f.write(analysis.stdout if analysis.stdout.strip() else "No se detectaron solicitudes/respuestas HTTP con este filtro.\n")
    if analysis.returncode:f.write("\nERROR: "+analysis.stderr+"\n")
print("Wireshark: archivo "+str(pcap))
print("Wireshark: analisis "+str(info))
