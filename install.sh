#!/bin/bash

# Wazuh IP Reputation Checker - Script de Instalación
# Compatible con Ubuntu 22.04
# Autor: juanpadiaz
# Versión: 1.0

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Variables
INSTALL_DIR="/opt/wazuh-ip-reputation"
SERVICE_NAME="wazuh-ip-reputation"
SERVICE_USER="wazuh-reputation"
LOG_FILE="/var/log/wazuh-ip-reputation-install.log"

# Función para logging
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    echo "[ERROR] $1" >> "$LOG_FILE"
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING] $1${NC}"
    echo "[WARNING] $1" >> "$LOG_FILE"
}

info() {
    echo -e "${BLUE}[INFO] $1${NC}"
    echo "[INFO] $1" >> "$LOG_FILE"
}

# Verificar que se ejecuta como root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        error "Este script debe ejecutarse como root (sudo)"
    fi
}

# Verificar sistema operativo
check_os() {
    if [[ ! -f /etc/os-release ]]; then
        error "No se puede determinar el sistema operativo"
    fi
    
    source /etc/os-release
    
    if [[ "$ID" != "ubuntu" ]]; then
        error "Este script está diseñado para Ubuntu. SO detectado: $ID"
    fi
    
    if [[ "$VERSION_ID" != "22.04" ]]; then
        warning "Este script está optimizado para Ubuntu 22.04. Versión detectada: $VERSION_ID"
    fi
    
    log "Sistema operativo verificado: Ubuntu $VERSION_ID"
}

# Actualizar sistema
update_system() {
    log "Actualizando sistema..."
    apt-get update -y >> "$LOG_FILE" 2>&1
    apt-get upgrade -y >> "$LOG_FILE" 2>&1
    log "Sistema actualizado correctamente"
}

# Instalar dependencias
install_dependencies() {
    log "Instalando dependencias del sistema..."
    
    # Paquetes básicos
    apt-get install -y \
        python3 \
        python3-pip \
        python3-venv \
        sqlite3 \
        curl \
        wget \
        git \
        systemd \
        cron \
        logrotate \
        >> "$LOG_FILE" 2>&1
    
    log "Dependencias del sistema instaladas"
}

# Crear usuario del servicio
create_service_user() {
    log "Creando usuario del servicio..."
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
        log "Usuario $SERVICE_USER creado"
    else
        log "Usuario $SERVICE_USER ya existe"
    fi
}

# Crear directorio de instalación
create_directories() {
    log "Creando directorios..."
    
    # Crear directorio principal
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$INSTALL_DIR/logs"
    mkdir -p "$INSTALL_DIR/backup"
    
    # Crear directorio de logs
    mkdir -p "/var/log"
    
    # Permisos
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR"
    
    log "Directorios creados correctamente"
}

# Crear entorno virtual Python
create_python_env() {
    log "Creando entorno virtual Python..."
    
    cd "$INSTALL_DIR"
    python3 -m venv venv
    
    # Activar entorno virtual e instalar dependencias
    source venv/bin/activate
    
    # Actualizar pip
    pip install --upgrade pip >> "$LOG_FILE" 2>&1
    
    # Instalar dependencias Python
    pip install \
        requests \
        sqlite3 \
        configparser \
        >> "$LOG_FILE" 2>&1
    
    deactivate
    
    # Permisos
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/venv"
    
    log "Entorno virtual Python creado"
}

# Descargar/copiar archivos del proyecto
install_project_files() {
    log "Instalando archivos del proyecto..."
    
    # Crear archivo principal del script
    cat > "$INSTALL_DIR/wazuh_ip_reputation.py" << 'EOF'
# El contenido del script principal se copiará aquí
# Durante la instalación real, este archivo debe estar disponible
EOF
    
    # Crear archivo de configuración por defecto
    cat > "$INSTALL_DIR/config.default" << 'EOF'
# Archivo de configuración por defecto
# Copiar a 'config' y modificar según sea necesario
EOF
    
    # Si no existe config, crear desde default
    if [[ ! -f "$INSTALL_DIR/config" ]]; then
        cp "$INSTALL_DIR/config.default" "$INSTALL_DIR/config"
        log "Archivo de configuración creado desde template"
    else
        log "Archivo de configuración ya existe"
    fi
    
    # Permisos
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chmod 755 "$INSTALL_DIR/wazuh_ip_reputation.py"
    chmod 600 "$INSTALL_DIR/config"
    
    log "Archivos del proyecto instalados"
}

# Crear servicio systemd
create_systemd_service() {
    log "Creando servicio systemd..."
    
    cat > "/etc/systemd/system/$SERVICE_NAME.service" << EOF
[Unit]
Description=Wazuh IP Reputation Checker
After=network.target
Wants=network.target

[Service]
Type=simple
User=$SERVICE_USER
Group=$SERVICE_USER
WorkingDirectory=$INSTALL_DIR
Environment=PATH=$INSTALL_DIR/venv/bin
ExecStart=$INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/wazuh_ip_reputation.py --continuous
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

# Límites de seguridad
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR /var/log
ProtectKernelTunables=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictNamespaces=true

[Install]
WantedBy=multi-user.target
EOF
    
    # Recargar systemd
    systemctl daemon-reload
    
    log "Servicio systemd creado"
}

# Configurar logrotate
configure_logrotate() {
    log "Configurando logrotate..."
    
    cat > "/etc/logrotate.d/$SERVICE_NAME" << EOF
/var/log/wazuh-ip-reputation.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 $SERVICE_USER $SERVICE_USER
    postrotate
        systemctl reload $SERVICE_NAME > /dev/null 2>&1 || true
    endscript
}
EOF
    
    log "Logrotate configurado"
}

# Configurar firewall (si está habilitado)
configure_firewall() {
    log "Verificando configuración de firewall..."
    
    if systemctl is-active --quiet ufw; then
        log "UFW está activo, configurando reglas..."
        
        # Permitir conexiones salientes para APIs
        ufw allow out 443/tcp comment "VirusTotal/AbuseIPDB APIs"
        ufw allow out 80/tcp comment "HTTP APIs"
        
        # Permitir conexión a Wazuh Manager
        ufw allow out 55000/tcp comment "Wazuh Manager API"
        
        log "Reglas de firewall configuradas"
    else
        log "UFW no está activo, omitiendo configuración de firewall"
    fi
}

# Crear script de backup
create_backup_script() {
    log "Creando script de backup..."
    
    cat > "$INSTALL_DIR/backup.sh" << 'EOF'
#!/bin/bash

# Script de backup para Wazuh IP Reputation
BACKUP_DIR="/opt/wazuh-ip-reputation/backup"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
DB_FILE="/opt/wazuh-ip-reputation/ip_reputation.db"
CONFIG_FILE="/opt/wazuh-ip-reputation/config"

# Crear directorio de backup
mkdir -p "$BACKUP_DIR"

# Backup de base de datos
if [[ -f "$DB_FILE" ]]; then
    cp "$DB_FILE" "$BACKUP_DIR/ip_reputation_${TIMESTAMP}.db"
    echo "Backup de base de datos creado: ip_reputation_${TIMESTAMP}.db"
fi

# Backup de configuración
if [[ -f "$CONFIG_FILE" ]]; then
    cp "$CONFIG_FILE" "$BACKUP_DIR/config_${TIMESTAMP}"
    echo "Backup de configuración creado: config_${TIMESTAMP}"
fi

# Limpiar backups antiguos (mantener últimos 7 días)
find "$BACKUP_DIR" -name "*.db" -type f -mtime +7 -delete
find "$BACKUP_DIR" -name "config_*" -type f -mtime +7 -delete

echo "Backup completado: $TIMESTAMP"
EOF
    
    chmod +x "$INSTALL_DIR/backup.sh"
    chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/backup.sh"
    
    log "Script de backup creado"
}

# Configurar cron para backups
configure_cron() {
    log "Configurando cron para backups..."
    
    # Crear entrada en cron para backups diarios
    cat > "/etc/cron.d/$SERVICE_NAME" << EOF
# Backup diario de Wazuh IP Reputation
0 2 * * * $SERVICE_USER $INSTALL_DIR/backup.sh > /var/log/wazuh-ip-reputation-backup.log 2>&1
EOF
    
    log "Cron configurado para backups diarios"
}

# Crear script de monitoreo
create_monitoring_script() {
    log "Creando script de monitoreo..."
    
    cat > "$INSTALL_DIR/monitor.sh" << 'EOF'
#!/bin/bash

# Script de monitoreo para Wazuh IP Reputation
SERVICE_NAME="wazuh-ip-reputation"
LOG_FILE="/var/log/wazuh-ip-reputation-monitor.log"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

# Verificar estado del servicio
if ! systemctl is-active --quiet "$SERVICE_NAME"; then
    log_message "ERROR: Servicio $SERVICE_NAME no está activo"
    
    # Intentar reiniciar
    systemctl restart "$SERVICE_NAME"
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        log_message "INFO: Servicio $SERVICE_NAME reiniciado exitosamente"
    else
        log_message "ERROR: No se pudo reiniciar el servicio $SERVICE_NAME"
    fi
else
    log_message "INFO: Servicio $SERVICE_NAME está funcionando correctamente"
fi

# Verificar espacio en disco
DISK_USAGE=$(df /opt/wazuh-ip-reputation | awk 'NR==2 {print $5}' | sed 's/%//')
if [[ $DISK_USAGE -gt 90 ]]; then
    log_message "WARNING: Uso de disco alto: ${DISK_USAGE}%"
fi

# Verificar tamaño de base de datos
DB_SIZE=$(du -h /opt/wazuh-ip-reputation/ip_reputation.db 2>/dev/null | cut -f1)
if [[ -n "$DB_SIZE" ]]; then
    log_message "INFO: Tamaño de base de datos: $DB_SIZE"
fi
EOF
    
    chmod +x "$INSTALL_DIR/monitor.sh"
    chown "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR/monitor.sh"
    
    # Agregar al cron para monitoreo cada 5 minutos
    cat >> "/etc/cron.d/$SERVICE_NAME" << EOF
# Monitoreo cada 5 minutos
*/5 * * * * $SERVICE_USER $INSTALL_DIR/monitor.sh
EOF
    
    log "Script de monitoreo creado"
}

# Configurar SELinux (si está habilitado)
configure_selinux() {
    if command -v getenforce &> /dev/null; then
        if [[ "$(getenforce)" == "Enforcing" ]]; then
            log "SELinux está habilitado, configurando contextos..."
            
            # Configurar contextos SELinux
            semanage fcontext -a -t admin_home_t "$INSTALL_DIR(/.*)?" 2>/dev/null || true
            restorecon -R "$INSTALL_DIR" 2>/dev/null || true
            
            log "Contextos SELinux configurados"
        fi
    fi
}

# Mostrar información post-instalación
show_post_install_info() {
    log "Instalación completada exitosamente"
    
    echo -e "\n${GREEN}================================${NC}"
    echo -e "${GREEN} INSTALACIÓN COMPLETADA${NC}"
    echo -e "${GREEN}================================${NC}\n"
    
    info "Directorio de instalación: $INSTALL_DIR"
    info "Usuario del servicio: $SERVICE_USER"
    info "Archivo de configuración: $INSTALL_DIR/config"
    info "Archivo de logs: /var/log/wazuh-ip-reputation.log"
    
    echo -e "\n${YELLOW}PRÓXIMOS PASOS:${NC}"
    echo -e "1. Editar el archivo de configuración:"
    echo -e "   ${BLUE}sudo nano $INSTALL_DIR/config${NC}"
    echo -e ""
    echo -e "2. Configurar las API keys:"
    echo -e "   - VirusTotal: https://www.virustotal.com/gui/my-apikey"
    echo -e "   - AbuseIPDB: https://www.abuseipdb.com/account/api"
    echo -e ""
    echo -e "3. Configurar las credenciales de Wazuh Manager"
    echo -e ""
    echo -e "4. Configurar el servidor SMTP para alertas"
    echo -e ""
    echo -e "5. Iniciar el servicio:"
    echo -e "   ${BLUE}sudo systemctl start $SERVICE_NAME${NC}"
    echo -e ""
    echo -e "6. Habilitar inicio automático:"
    echo -e "   ${BLUE}sudo systemctl enable $SERVICE_NAME${NC}"
    echo -e ""
    echo -e "7. Verificar estado:"
    echo -e "   ${BLUE}sudo systemctl status $SERVICE_NAME${NC}"
    echo -e ""
    echo -e "8. Ver logs:"
    echo -e "   ${BLUE}sudo journalctl -u $SERVICE_NAME -f${NC}"
    echo -e ""
    
    echo -e "${YELLOW}COMANDOS ÚTILES:${NC}"
    echo -e "- Ejecutar análisis único: ${BLUE}sudo -u $SERVICE_USER $INSTALL_DIR/venv/bin/python3 $INSTALL_DIR/wazuh_ip_reputation.py --once${NC}"
    echo -e "- Backup manual: ${BLUE}sudo -u $SERVICE_USER $INSTALL_DIR/backup.sh${NC}"
    echo -e "- Monitoreo manual: ${BLUE}sudo -u $SERVICE_USER $INSTALL_DIR/monitor.sh${NC}"
    echo -e ""
    
    warning "IMPORTANTE: Asegúrate de configurar las API keys antes de iniciar el servicio"
}

# Función principal
main() {
    log "Iniciando instalación de Wazuh IP Reputation Checker"
    
    check_root
    check_os
    update_system
    install_dependencies
    create_service_user
    create_directories
    create_python_env
    install_project_files
    create_systemd_service
    configure_logrotate
    configure_firewall
    create_backup_script
    configure_cron
    create_monitoring_script
    configure_selinux
    
    show_post_install_info
}

# Manejo de errores
trap 'error "Instalación fallida en la línea $LINENO"' ERR

# Ejecutar instalación
main "$@"
