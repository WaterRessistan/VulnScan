#!/bin/bash

# Colores para la terminal
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}[*] Iniciando instalación de dependencias para VulnScan...${NC}"

# Actualizar repositorios
sudo apt update

# Instalar Nmap
echo -e "${GREEN}[*] Instalando Nmap...${NC}"
sudo apt install -y nmap

# Instalar Searchsploit (ExploitDB)
echo -e "${GREEN}[*] Instalando ExploitDB (Searchsploit)...${NC}"
sudo apt install -y exploitdb

# Verificar si Python3 está instalado
if command -v python3 &>/dev/null; then
    echo -e "${GREEN}[V] Python3 ya está instalado.${NC}"
else
    echo -e "${RED}[X] Python3 no encontrado. Instalando...${NC}"
    sudo apt install -y python3
fi

echo -e "${GREEN}[V] ¡Todo listo! Ahora puedes ejecutar: sudo python3 VulScan.py${NC}"