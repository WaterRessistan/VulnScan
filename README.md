# VulnScan 🛡️ 
**Desarrollado por WaterRessistan**

VulnScan es una herramienta avanzada de reconocimiento y auditoría de red diseñada para identificar servicios, detectar versiones vulnerables y mapear automáticamente posibles exploits utilizando la base de datos de Exploit-DB.

> **Nota:** Este proyecto está protegido bajo una licencia **No Comercial**. Queda prohibida su venta o uso para beneficio económico sin autorización.

---

## 📁 Estructura del Proyecto

* `VulnScan.py`: El núcleo del escáner (lógica de red y detección).
* `setup.sh`: Script de automatización para configurar el entorno en Linux.
* `requirements.txt`: Dependencias de Python necesarias.
* `LICENSE`: Términos legales de uso (CC BY-NC-SA 4.0).
* `README.md`: Documentación técnica.

---

## ✨ Características Principales

* 🔍 **Escaneo Masivo:** Optimizado para procesar múltiples IPs y rangos CIDR en una sola ejecución.
* 🦠 **Detección Crítica:** Algoritmos específicos para identificar **EternalBlue (MS17-010)**.
* 🧹 **Limpieza Inteligente:** Procesamiento de banners de servicios (Samba, Apache, etc.) para evitar falsos negativos.
* 🎯 **Mapeo de Exploits:** Integración directa con `searchsploit` para obtener IDs de vulnerabilidades en tiempo real.
* 📊 **Reportes Visuales:** Salida organizada en tablas con códigos de colores para una lectura rápida.

---

## 🛠️ Instalación

Gracias al archivo `setup.sh`, la configuración es automática. Abre una terminal en la carpeta del proyecto y ejecuta:

1. **Dar permisos de ejecución al instalador:**
```bash
   chmod +x setup.sh
```
2. **Ejecutar el instalador (instalará Nmap, Searchsploit y dependencias)::**
```bash
   sudo ./setup.sh
```
3. **Instalar dependencias de Python:**
```bash
   pip install -r requirements.txt      
```

## 🚀 Modo de Uso

> **Importante:** El script requiere privilegios de **root** debido al uso de funciones avanzadas de Nmap, como la detección de versiones (`-sV`) y la huella digital del sistema operativo (`-O`).

### ❓ Obtener Ayuda
Si necesitas consultar los parámetros disponibles o la guía rápida de uso, ejecuta:
```bash
python3 VulnScan.py -h
# o también
python3 VulnScan.py --help

   