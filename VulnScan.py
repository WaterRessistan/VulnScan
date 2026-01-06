# ----------------------------------------------------------------------------------
# Herramienta: VulnScan
# Autor: WaterRessistan
# Fecha: 2026
#
# LICENCIA: Creative Commons Attribution-NonCommercial-ShareAlike 4.0 International
# 
# Usted es libre de:
# - Compartir, copiar y redistribuir el material en cualquier medio o formato.
# - Adaptar, remezclar, transformar y construir sobre el material.
#
# Bajo las siguientes condiciones:
# - ATRIBUCIÓN: Debe reconocer la autoría de WaterRessistan.
# - NO COMERCIAL: No puede utilizar este material para fines comerciales.
# - COMPARTIR IGUAL: Si altera o transforma este código, debe distribuir su
#   trabajo bajo la misma licencia que el original.
# ----------------------------------------------------------------------------------

import subprocess
import re
import ipaddress
import xml.etree.ElementTree as ET
import json
import sys
import time
import threading
import os

# Definición de colores para la terminal
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
RESET = "\033[0m"  # Muy importante para que el resto del texto no siga rojo


def imprimir_banner():
    # Arte ASCII estilo "Slant"
    banner_ascii = r"""
   _    __      __      _____
  | |  / /_  __/ /___  / ___/_________ _____
  | | / / / / / / __ \ \ __ \/ ___/ __ `/ __ \
  | |/ / /_/ / / / / / ___/ / /__/ /_/ / / / /
  |___/\__,_/_/_/ /_//____/ \___/\__,_/_/ /_/
"""
    print(f"{CYAN}{banner_ascii}{RESET}")
    # Centramos un poco el subtítulo con espacios
    print(f"{GREEN}             Made by WaterRessistan{RESET}")
    print(f"\n{BLUE}{'='*60}{RESET}\n")


def verificar_dependencias():
    for cmd in ["nmap", "searchsploit"]:
        if subprocess.run(["which", cmd], capture_output=True).returncode != 0:
            print(f"{RED}[!] Error: {cmd} no está instalado.{RESET}")
            sys.exit(1)

def animacion_carga(stop_event):
    """Muestra una barra de carga animada mientras el evento no se detenga."""
    chars = ["|", "/", "-", "\\"]
    idx = 0
    while not stop_event.is_set():
        # Animación de barra de progreso sencilla
        bar = "■" * (idx % 11) + " " * (10 - (idx % 11))
        sys.stdout.write(f"\r    {BLUE}[{chars[idx % len(chars)]}] Escaneando: [{bar}] {RESET}")
        sys.stdout.flush()
        idx += 1
        time.sleep(0.1)
    # Al terminar, limpiamos la línea
    sys.stdout.write("\r" + " " * 60 + "\r")
    sys.stdout.flush()

def escaneo(red):

    if not red:
        print(f"{RED}[!] No hay red disponible para el escaneo.{RESET}")
        return []

    comando = [
        "sudo", "nmap", 
        "-Pn",
        "-sV", 
        "-O",
        "--osscan-guess", 
        "-T4", 
        "--min-rate", "2000", 
        "--max-retries", "2", 
        "--version-intensity", "0", 
        "-n",  
        "--min-hostgroup", "64", 
        "-oX", "-", 
        str(red)
    ]

    resultados_locales = []

    if os.geteuid() != 0:
        print(f"\n{RED}[!] ERROR: Este script debe ejecutarse con privilegios de superusuario (sudo).{RESET}")
        print(f"{YELLOW}[*] Uso sugerido: sudo python3 VulScan.py{RESET}\n")
        sys.exit(1)
    # Evento para detener la animación
    stop_animacion = threading.Event()
    hilo_animacion = threading.Thread(target=animacion_carga, args=(stop_animacion,))

    try:
  
        print(f"    {YELLOW}[!] Analizando servicios y versiones en {red}...{RESET}")
        #print(f"    {YELLOW}[!] Este proceso suele tardar en función del número de hosts.{RESET}")

        # Iniciamos la animación
        hilo_animacion.start()

        proceso = subprocess.run(comando, capture_output=True, text=True, check=True)

        # Detenemos la animación
        stop_animacion.set()
        hilo_animacion.join()
        
        print(f"    {GREEN}[V] Escaneo completado.{RESET}")

        xml_data = proceso.stdout
        root = ET.fromstring(xml_data)
        for host in root.findall('host'):
            ip = host.find('address').get('addr')
            os_name = "Desconocido"
            os_element = host.find('.//osmatch')
            if os_element is not None:
                os_name = os_element.get('name')

            for port in host.findall('.//port'):
                state = port.find('state').get('state')
                if state == 'open':
                    portid = port.get('portid')
                    service = port.find('service')
                    
                    version_info = "Unknown"
                    if service is not None:
                        product = service.get('product', '')
                        version = service.get('version', '')
                        extrainfo = service.get('extrainfo', '')
                        version_info = f"{product} {version} {extrainfo}".strip() or "Unknown"
                        # --- LÓGICA DE LIMPIEZA ESPECÍFICA PARA SAMBA ---
                        if "Samba" in version_info:
                            # 1. Quitamos la palabra "smbd" que suele estorbar
                            version_info = version_info.replace("smbd ", "") 
                            # 2. Quitamos "workgroup:" y todo lo que venga después
                        if "workgroup:" in version_info.lower():
                            # Partimos la cadena en "workgroup:" y nos quedamos solo con la primera parte
                            version_info = re.split(r'workgroup:', version_info, flags=re.IGNORECASE)[0]
                            
                            # 3. Limpiamos paréntesis sobrantes y espacios extra
                            version_info = version_info.replace("(", "").replace(")", "").strip()
                        # -----------------------------------------------

                    resultados_locales.append({
                        "ip": ip,
                        "puerto": portid,
                        "version": version_info,
                        "os": os_name
                    })
    except KeyboardInterrupt:
        print("\n[x] Escaneo cancelado por el usuario.")
        stop_animacion.set()
    except subprocess.CalledProcessError as e:
        print(f"[!] Error crítico en Nmap: {e.stderr}")
        stop_animacion.set()
    except Exception as e:
        print(f"[!] Error inesperado: {e}")
        stop_animacion.set()
    
    return resultados_locales

def obtener_redes():
    print(f"{'Interfaz':<15} | {'Dirección IP':<15} | {'Red (CIDR)':<18}")
    print("-" * 52)
    redes = []
    try:
        resultado = subprocess.check_output(["ip", "-4", "addr", "show"], text=True)
        interfaces = re.findall(r'^\d+: (\w+):.*?\s+inet ([\d\.]+/\d+)', resultado, re.DOTALL | re.MULTILINE)
        for nombre, cidr in interfaces:
            if nombre == "lo": continue
            interfaz_red = ipaddress.IPv4Interface(cidr)
            red = interfaz_red.network
            redes.append(red)
            print(f"{nombre:<15} | {str(interfaz_red.ip):<15} | {str(red):<18}") 
    except Exception as e:
        print(f"Error al obtener la información de red: {e}")
    return redes    


def escaneo_de_redes(redes):
    todas_las_versiones = []
    for red in redes:
        print(f"\n[+] Iniciando escaneo en la red: {red}")
        resultados_red = escaneo(red)
        todas_las_versiones.extend(resultados_red)
    return todas_las_versiones


def buscar_exploits(servicios):
    if not servicios:
        return
    print(f"\n[+] Iniciando búsqueda de exploits en Searchsploit...")
    for s in servicios:
        version = s['version']
        print(f"    [*] Buscando para: {version} ({s['ip']})")
        try:
            comando = ["searchsploit", "--json", version]
            proceso = subprocess.run(comando, capture_output=True, text=True)
            if proceso.stdout:
                datos = json.loads(proceso.stdout)
                resultados = datos.get("RESULTS_EXPLOIT", [])
                if resultados:
                    print(f"    {GREEN}[!] ¡Se encontraron {len(resultados)} posibles exploits!{RESET}")
                    for x in resultados:
                        print(f"        - {x['Title']} [ID: {x['EDB-ID']}]")
                else:
                    print(f"        Sin resultados directos.")
        except FileNotFoundError:
            print("[!] Error: 'searchsploit' no está instalado.")
            break
        except Exception as e:
            print(f"[!] Error al buscar exploit: {e}")


def obtener_cve(version_texto):
    """
    Recibe una cadena de texto (ej. 'vsftpd 2.3.4') y devuelve 
    el CVE asociado si existe en la base de datos local.
    """
    # Base de datos local de WaterRessistan: Patrón Regex -> CVE
    db_vulnerabilidades = {
        # --- Servicios Web e Infraestructura ---
    r"^Apache httpd 2\.4\.49": "CVE-2021-41773",
    r"^Apache 2\.4\.10": "CVE-2014-3581",
    r"^Apache 2\.2\.0": "CVE-2007-3304",
    r"^nginx 1\.4\.0": "CVE-2013-2028",
    r"^nginx 1\.2\.0": "CVE-2013-2028",
    r"^Microsoft IIS 6\.0": "CVE-2017-7269",
    r"^Microsoft IIS 7\.0": "CVE-2010-2730",
    
    # --- Transferencia de Archivos y Shell ---
    r"^vsftpd 2\.3\.4": "CVE-2011-2523 (Backdoor)",
    r"^vsftpd 2\.0\.8": "CVE-2011-0762",
    r"^ProFTPD 1\.3\.5": "CVE-2015-3306",
    r"^ProFTPD 1\.3\.4": "CVE-2012-6065",
    r"^ProFTPD 1\.2\.9": "CVE-2003-0831",
    r"^OpenSSH 7\.2p2": "CVE-2016-6210",
    r"^OpenSSH 5\.3": "CVE-2010-4478",
    r"^OpenSSH 4\.3": "CVE-2006-5051",
    
    # --- Bases de Datos y Almacenamiento ---
    r"^MySQL 5\.5\.31": "CVE-2012-2122",
    r"^MySQL 5\.1\.73": "CVE-2012-2122",
    r"^PostgreSQL 9\.3\.0": "CVE-2014-0067",
    r"^PostgreSQL 8\.4\.0": "CVE-2010-0733",
    r"^MongoDB 2\.6\.0": "CVE-2015-1609",
    r"^MongoDB 2\.4\.0": "CVE-2013-1892",
    r"^Redis 3\.0\.0": "CVE-2015-8080",
    r"^Redis 2\.4\.0": "CVE-2013-7458",
    r"^Elasticsearch 1\.4\.0": "CVE-2015-1427",
    r"^Elasticsearch 0\.90\.0": "CVE-2014-3120",
    
    # --- CMS y Aplicaciones ---
    r"^WordPress 4\.7\.0": "CVE-2017-1001000",
    r"^WordPress 3\.0\.1": "CVE-2011-3122",
    r"^Joomla! 3\.4\.6": "CVE-2015-7297",
    r"^Joomla! 2\.5\.0": "CVE-2012-6039",
    r"^Drupal 7\.32": "CVE-2014-3704 (Drupalgeddon)",
    r"^Drupal 6\.19": "CVE-2010-3077",
    r"^PHP 5\.3\.3": "CVE-2012-1823",
    r"^PHP 5\.2\.17": "CVE-2012-1823",
    r"^Tomcat 7\.0\.27": "CVE-2012-0022",
    r"^Tomcat 6\.0\.35": "CVE-2012-0022",
    
    # --- Otros Servicios de Red ---
    r"^Samba 3\.6\.25": "CVE-2015-0240",
    r"^Samba 3\.5\.0": "CVE-2012-1182",
    r"^OpenSSL 1\.0\.1": "CVE-2014-0160 (Heartbleed)",
    r"^OpenSSL 0\.9\.8": "CVE-2009-3555",
    r"^OpenVPN 2\.3\.2": "CVE-2014-8104",
    r"^OpenVPN 2\.2\.0": "CVE-2013-2061",
    r"^Bind 9\.9\.5": "CVE-2014-8500",
    r"^Bind 9\.7\.0": "CVE-2011-2464",
    r"^Dovecot 2\.2\.13": "CVE-2014-3430",
    r"^Dovecot 1\.2\.0": "CVE-2010-0745",
    r"^Exim 4\.80": "CVE-2014-0476",
    r"^Exim 4\.70": "CVE-2010-4344",
    r"^UnrealIRCd 3\.2\.8\.1": "CVE-2010-2075 (Backdoor)"
        
    }

    for patron, cve in db_vulnerabilidades.items():
        if re.search(patron, version_texto, re.IGNORECASE):
            return cve
            
    return "CVE-DESCONOCIDO"


def vulnerable(lista_servicios):
    patrones_vulnerables = [
        r"^OpenSSH 7\.2p2", r"^Apache httpd 2\.4\.49", r"^ProFTPD 1\.3\.5",
        r"^vsftpd 2\.3\.4", r"^Microsoft IIS 6\.0", r"^nginx 1\.4\.0",
        r"^OpenSSL 1\.0\.1", r"^PHP 5\.3\.3", r"^MySQL 5\.5\.31",
        r"^Tomcat 7\.0\.27", r"^Joomla! 3\.4\.6", r"^Drupal 7\.32",
        r"^WordPress 4\.7\.0", r"^Samba 3\.6\.25", r"^Redis 3\.0\.0",
        r"^Elasticsearch 1\.4\.0", r"^MongoDB 2\.6\.0", r"^PostgreSQL 9\.3\.0",
        r"^OpenVPN 2\.3\.2", r"^Bind 9\.9\.5", r"^Dovecot 2\.2\.13",
        r"^Exim 4\.80", r"^Apache 2\.4\.10", r"^OpenSSH 5\.3",
        r"^ProFTPD 1\.3\.4", r"^vsftpd 2\.0\.8", r"^Microsoft IIS 7\.0",
        r"^nginx 1\.2\.0", r"^OpenSSL 0\.9\.8", r"^PHP 5\.2\.17",
        r"^MySQL 5\.1\.73", r"^Tomcat 6\.0\.35", r"^Joomla! 2\.5\.0",
        r"^Drupal 6\.19", r"^WordPress 3\.0\.1", r"^Samba 3\.5\.0",
        r"^Redis 2\.4\.0", r"^Elasticsearch 0\.90\.0", r"^MongoDB 2\.4\.0",
        r"^PostgreSQL 8\.4\.0", r"^OpenVPN 2\.2\.0", r"^Bind 9\.7\.0",
        r"^Dovecot 1\.2\.0", r"^Exim 4\.70", r"^Apache 2\.2\.0",
        r"^OpenSSH 4\.3", r"^ProFTPD 1\.2\.9", r"^UnrealIRCd 3\.2\.8\.1"
    ]

    for s in lista_servicios:
        version_actual = s['version']
        ip_actual = s['ip']
        os_actual = s.get('os', 'Desconocido') # Obtenemos el OS
        hallado_local = False

        # --- DETECCIÓN ESPECÍFICA DE ETERNALBLUE ---
        es_windows_7 = "Windows 7" in version_actual or "Windows 7" in os_actual
        es_smb = "microsoft-ds" in version_actual.lower()

        if es_windows_7 and es_smb:
            print(f"\n{RED}[!!!] ALERTA CRÍTICA en {ip_actual}: POSIBLE ETERNALBLUE (MS17-010){RESET}")
            print(f"    {YELLOW}OS: {os_actual} | Servicio: {version_actual}{RESET}")
            print(f"    {RED}CVE asociado: CVE-2017-0144{RESET}")
            buscar_exploits([{"version": "MS17-010", "ip": ip_actual}]) # Forzamos búsqueda exacta
            hallado_local = True
            continue # Pasamos al siguiente servicio

        for patron in patrones_vulnerables:
            if re.search(patron, version_actual, re.IGNORECASE):
                print(f"\n {RED}[!] ¡CRÍTICO!: Servicio vulnerable en {ip_actual} -> {version_actual}.{RESET}")               
                if obtener_cve(version_actual) != "CVE-DESCONOCIDO":
                    print(f"     {RED}CVE asociado: {obtener_cve(version_actual)}{RESET}")
                buscar_exploits([s])
                hallado_local = True
                break

        if not hallado_local:
            print(f"\n{YELLOW}[*] Sin coincidencia local crítica para {ip_actual} ({version_actual}).{RESET}")
            buscar_exploits([s])

if __name__ == "__main__":

    verificar_dependencias()
    imprimir_banner()
    
    servicios_finales = []
    redes_para_escanear = []

# --- LÓGICA DE ARGUMENTOS MODIFICADA PARA MÚLTIPLES IPS ---
    # sys.argv[1:] captura todos los argumentos que pongas después del nombre del script
    num_args = len(sys.argv) - 1

    if num_args >= 1:

        if sys.argv[1] in ["-h", "--help"]:
            print(f"{CYAN}Uso: sudo python3 VulnScan.py [red1/IP1] [red2/IP2] ...{RESET}")
            print("Ejemplo: sudo python3 VulnScan.py 192.168.1.0/24 10.0.0.0/8")
            print("Ejemplo: sudo python3 VulnScan.py 192.168.1.172 192.168.1.173 192.168.1.174")
            print("Ejemplo: sudo python3 VulnScan.py 192.168.1.172 10.0.0.0/24")
            sys.exit(0)

        # Guardamos todos los argumentos en la lista
        redes_para_escanear = sys.argv[1:]
        
        # Formateamos el mensaje dependiendo de si es uno o varios
        targets_str = ", ".join(redes_para_escanear)
        print(f"{YELLOW}[!] {num_args} objetivo(s) detectado(s): {targets_str}{RESET}")
    else:
        print(f"{CYAN}[*] No se detectaron argumentos. Escaneando redes locales...{RESET}")
        redes_para_escanear = obtener_redes()

    # Ejecución del escaneo
    if redes_para_escanear:
        servicios_detectados = escaneo_de_redes(redes_para_escanear)

        print(f"\n{'='*30} RESUMEN DE DISPOSITIVOS {'='*30}")
        # Cabecera de la tabla para mayor claridad
        header = f"{'DIRECCIÓN IP':<15} | {'SISTEMA OPERATIVO':<25} | {'PUERTO':<6} | {'VERSIÓN'}"
        print(f"{BLUE}{header}{RESET}")
        print("-" * len(header))

        if servicios_detectados:
            for s in servicios_detectados:
                # Obtenemos el OS (asegúrate de que tu función escaneo lo extraiga)
                os_info = s.get('os', 'Desconocido')
                
                # Recortamos el nombre del OS si es demasiado largo para la tabla
                os_display = (os_info[:22] + '...') if len(os_info) > 25 else os_info

                print(f"{s['ip']:<15} | {YELLOW}{os_display:<25}{RESET} | {s['puerto']:<6} | {s['version']}")
                
                if s['version'] != "Unknown":
                    servicios_finales.append(s)
        else:
            print(f"{RED}No se encontraron servicios abiertos.{RESET}")

        if servicios_finales:
            print(f"\n{'='*25} COMPROBANDO VULNERABILIDADES {'='*25}")
            vulnerable(servicios_finales)

        