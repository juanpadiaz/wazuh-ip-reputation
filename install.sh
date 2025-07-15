#!/bin/bash

# Script de instalación para Wazuh IP Reputation Checker
# Ubuntu 22.04 LTS

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}=== Instalador de Wazuh IP Reputation Checker ===${NC}"

# Verificar usuario root
if [[ $EUID -eq 0 ]]; then
   echo -e "${RED}Este script no debe ejecutarse como root${NC}"
   exit 1
fi

# Crear directorio de trabajo
INSTALL_DIR="/opt/wazuh-ip-reputation"
echo -e "${YELLOW}Creando directorio de instalación...${NC}"
sudo mkdir -p $INSTALL_DIR
sudo chown $USER:$USER $INSTALL_DIR

# Actualizar sistema
echo -e "${YELLOW}Actualizando sistema...${NC}"
sudo apt update

# Instalar Python 3 y pip si no están instalados
echo -e "${YELLOW}Instalando dependencias del sistema...${NC}"
sudo apt install -y python3 python3-pip python3-venv

# Crear entorno virtual
echo -e "${YELLOW}Creando entorno virtual...${NC}"
cd $INSTALL_DIR
python3 -m venv venv

# Activar entorno virtual
source venv/bin/activate

# Instalar dependencias Python
echo -e "${YELLOW}Instalando dependencias Python...${NC}"
pip install --upgrade pip
pip install requests configparser

# Crear directorio de logs
mkdir -p logs

# Copiar archivos si existen en directorio actual
if [ -f "wazuh_ip_reputation.py" ]; then
    cp wazuh_ip_reputation.py $INSTALL_DIR/
    echo -e "${GREEN}Archivo principal copiado${NC}"
fi

if [ -f "config" ]; then
    cp config $INSTALL_DIR/
    echo -e "${GREEN}Archivo de configuración copiado${NC}"
fi

if [ -f "requirements.txt" ]; then
    cp requirements.txt $INSTALL_DIR/
    echo -e "${GREEN}Archivo requirements.txt copiado${NC}"
fi

# Crear script de inicio
cat > $INSTALL_DIR/start.sh << 'EOF'
#!/bin/bash
cd /opt/wazuh-ip-reputation
source venv/bin/activate
python3 wazuh_ip_reputation.py --continuous
EOF

chmod +x $INSTALL_DIR/start.sh

# Crear servicio systemd
echo -e "${YELLOW}Creando servicio systemd...${NC}"
sudo tee /etc/systemd/system/wazuh-ip-reputation.service > /dev/null << EOF
[Unit]
Description=Wazuh IP Reputation Checker
After=network.target

[Service]
Type=simple
User=$USER
WorkingDirectory=$INSTALL_DIR
ExecStart=$INSTALL_DIR/start.sh
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Recargar systemd
sudo systemctl daemon-reload

# Crear script de configuración
cat > $INSTALL_DIR/configure.sh << 'EOF'
#!/bin/bash

echo "=== Configuración de Wazuh IP Reputation Checker ==="
echo ""

# Verificar si existe archivo de configuración
if [ ! -f "config" ]; then
    echo "ERROR: Archivo de configuración no encontrado"
    exit 1
fi

echo "Por favor, edite el archivo de configuración:"
echo "nano config"
echo ""
echo "Configure los siguientes parámetros:"
echo "1. API Keys (VirusTotal y AbuseIPDB)"
echo "2. Configuración de Wazuh"
echo "3. Configuración de email"
echo ""
echo "Después de configurar, ejecute:"
echo "sudo systemctl enable wazuh-ip-reputation"
echo "sudo systemctl start wazuh-ip-reputation"
EOF

chmod +x $INSTALL_DIR/configure.sh

# Crear script de logs
cat > $INSTALL_DIR/view_logs.sh << 'EOF'
#!/bin/bash
echo "=== Logs del servicio ==="
sudo journalctl -u wazuh-ip-reputation -f
EOF

chmod +x $INSTALL_DIR/view_logs.sh

# Crear script de estado
cat > $INSTALL_DIR/status.sh << 'EOF'
#!/bin/bash
echo "=== Estado del servicio ==="
sudo systemctl status wazuh-ip-reputation
EOF

chmod +x $INSTALL_DIR/status.sh

# Información final
echo -e "${GREEN}=== Instalación completada ===${NC}"
echo ""
echo -e "${YELLOW}Pasos siguientes:${NC}"
echo "1. Ir al directorio de instalación:"
echo "   cd $INSTALL_DIR"
echo ""
echo "2. Configurar el archivo config:"
echo "   nano config"
echo ""
echo "3. Habilitar y iniciar el servicio:"
echo "   sudo systemctl enable wazuh-ip-reputation"
echo "   sudo systemctl start wazuh-ip-reputation"
echo ""
echo "4. Ver logs:"
echo "   ./view_logs.sh"
echo ""
echo "5. Ver estado:"
echo "   ./status.sh"
echo ""
echo -e "${GREEN}Instalación en: $INSTALL_DIR${NC}"
