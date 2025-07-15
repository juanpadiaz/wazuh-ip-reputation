#!/bin/bash

# Wazuh IP Reputation Checker - Script de Desinstalación
# Compatible con Ubuntu 22.04

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
LOG_FILE="/var/log/wazuh-ip-reputation-uninstall.log"

# Función para logging
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR] $1${NC}"
    echo "[ERROR] $1" >> "$LOG_FILE"
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
        exit 1
    fi
}

# Confirmar desinstalación
confirm_uninstall() {
    echo -e "${YELLOW}⚠️  ADVERTENCIA: Esta acción eliminará completamente el sistema Wazuh IP Reputation${NC}"
    echo -e "${YELLOW}   Esto incluye:${NC}"
    echo -e "${YELLOW}   - Todos los archivos del sistema${NC}"
    echo -e "${YELLOW}   - Base de datos con histórico de IPs${NC}"
    echo -e "${YELLOW}   - Configuración y logs${NC}"
    echo -e "${YELLOW}   - Usuario del sistema${NC}"
    echo -e "${YELLOW}   - Servicio systemd${NC}"
    echo ""
    
    read -p "¿Está seguro que desea continuar? (escriba 'CONFIRMAR' para proceder): " confirm
    
    if [[ "$confirm" != "CONFIRMAR" ]]; then
        info "Desinstalación cancelada por el usuario"
        exit 0
    fi
}

# Ofrecer backup antes de desinstalar
offer_backup() {
    echo -e "${BLUE}¿Desea crear un backup antes de desinstalar? (y/n)${NC}"
    read -p "Respuesta: " backup_choice
    
    if [[ "$backup_choice" =~ ^[Yy]$ ]]; then
        create_final_backup
    fi
}

# Crear backup final
create_final_backup() {
    log "Creando backup final antes de desinstalar..."
    
    BACKUP_DIR="/tmp/wazuh-ip-reputation-backup-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    if [[ -d "$INSTALL_DIR" ]]; then
        # Backup de toda la instalación
        cp -r "$INSTALL_DIR" "$BACKUP_DIR/"
        
        # Crear archivo de información del backup
        cat > "$BACKUP_DIR/backup_info.txt" << EOF
Backup creado el: $(date)
Versión del sistema: $(cat /etc/os-release | grep VERSION= | cut -d'"' -f2)
Usuario que ejecutó: $SUDO_USER
Razón: Desinstalación del sistema

Contenido del backup:
- Directorio completo: $INSTALL_DIR
- Base de datos: ip_reputation.db
- Configuración: config
- Scripts: *.sh, *.py
- Logs: logs/

Para restaurar:
1. Ejecutar install.sh nuevamente
2. Copiar archivos de configuración
3. Restaurar base de datos
EOF
        
        log "Backup creado en: $BACKUP_DIR"
        info "IMPORTANTE: Guarde este backup en un lugar seguro"
    else
        warning "No se encontró directorio de instalación para backup"
    fi
}

# Detener servicio
stop_service() {
    log "Deteniendo servicio $SERVICE_NAME..."
    
    if systemctl is-active --quiet "$SERVICE_NAME"; then
        systemctl stop "$SERVICE_NAME" || warning "No se pudo detener el servicio"
        log "Servicio detenido"
    else
        log "Servicio no estaba ejecutándose"
    fi
    
    if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
        systemctl disable "$SERVICE_NAME" || warning "No se pudo deshabilitar el servicio"
        log "Servicio deshabilitado"
    fi
}

# Eliminar servicio systemd
remove_systemd_service() {
    log "Eliminando servicio systemd..."
    
    SERVICE_FILE="/etc/systemd/system/$SERVICE_NAME.service"
    
    if [[ -f "$SERVICE_FILE" ]]; then
        rm -f "$SERVICE_FILE"
        systemctl daemon-reload
        log "Archivo de servicio eliminado"
    else
        log "Archivo de servicio no encontrado"
    fi
}

# Eliminar configuración de cron
remove_cron_config() {
    log "Eliminando configuración de cron..."
    
    CRON_FILE="/etc/cron.d/$SERVICE_NAME"
    
    if [[ -f "$CRON_FILE" ]]; then
        rm -f "$CRON_FILE"
        log "Archivo de cron eliminado"
    else
        log "Archivo de cron no encontrado"
    fi
}

# Eliminar configuración de logrotate
remove_logrotate_config() {
    log "Eliminando configuración de logrotate..."
    
    LOGROTATE_FILE="/etc/logrotate.d/$SERVICE_NAME"
    
    if [[ -f "$LOGROTATE_FILE" ]]; then
        rm -f "$LOGROTATE_FILE"
        log "Configuración de logrotate eliminada"
    else
        log "Configuración de logrotate no encontrada"
    fi
}

# Eliminar logs del sistema
remove_logs() {
    log "Eliminando logs del sistema..."
    
    # Lista de archivos de log a eliminar
    LOG_FILES=(
        "/var/log/wazuh-ip-reputation.log"
        "/var/log/wazuh-ip-reputation.log.*"
        "/var/log/wazuh-ip-reputation-backup.log"
        "/var/log/wazuh-ip-reputation-monitor.log"
        "/var/log/wazuh-ip-reputation-install.log"
    )
    
    for log_file in "${LOG_FILES[@]}"; do
        if ls $log_file 1> /dev/null 2>&1; then
            rm -f $log_file
            log "Eliminado: $log_file"
        fi
    done
}

# Eliminar directorio de instalación
remove_installation_directory() {
    log "Eliminando directorio de instalación..."
    
    if [[ -d "$INSTALL_DIR" ]]; then
        # Verificar que no hay procesos usando el directorio
        if lsof "$INSTALL_DIR" 2>/dev/null; then
            warning "Hay procesos usando $INSTALL_DIR, intentando terminarlos..."
            fuser -k "$INSTALL_DIR" 2>/dev/null || true
            sleep 2
        fi
        
        rm -rf "$INSTALL_DIR"
        log "Directorio de instalación eliminado"
    else
        log "Directorio de instalación no encontrado"
    fi
}

# Eliminar usuario del servicio
remove_service_user() {
    log "Eliminando usuario del servicio..."
    
    if id "$SERVICE_USER" &>/dev/null; then
        # Terminar procesos del usuario
        pkill -u "$SERVICE_USER" 2>/dev/null || true
        sleep 2
        
        # Eliminar usuario
        userdel "$SERVICE_USER" 2>/dev/null || warning "No se pudo eliminar el usuario $SERVICE_USER"
        
        # Eliminar directorio home si existe
        if [[ -d "/home/$SERVICE_USER" ]]; then
            rm -rf "/home/$SERVICE_USER"
        fi
        
        log "Usuario $SERVICE_USER eliminado"
    else
        log "Usuario $SERVICE_USER no encontrado"
    fi
}

# Limpiar configuración de firewall
cleanup_firewall() {
    log "Limpiando configuración de firewall..."
    
    if systemctl is-active --quiet ufw; then
        # Eliminar reglas específicas del servicio
        ufw --force delete allow out 443/tcp comment "VirusTotal/AbuseIPDB APIs" 2>/dev/null || true
        ufw --force delete allow out 80/tcp comment "HTTP APIs" 2>/dev/null || true
        ufw --force delete allow out 55000/tcp comment "Wazuh Manager API" 2>/dev/null || true
        
        log "Reglas de firewall eliminadas"
    else
        log "UFW no está activo, omitiendo limpieza de firewall"
    fi
}

# Limpiar dependencias Python (opcional)
cleanup_python_dependencies() {
    echo -e "${BLUE}¿Desea eliminar las dependencias Python instaladas? (y/n)${NC}"
    echo -e "${YELLOW}NOTA: Esto podría afectar otras aplicaciones Python${NC}"
    read -p "Respuesta: " cleanup_choice
    
    if [[ "$cleanup_choice" =~ ^[Yy]$ ]]; then
        log "Limpiando dependencias Python..."
        
        # Lista de paquetes instalados específicamente para este proyecto
        pip3 uninstall -y requests configparser 2>/dev/null || true
        
        log "Dependencias Python eliminadas"
    else
        log "Manteniendo dependencias Python"
    fi
}

# Verificar desinstalación completa
verify_uninstall() {
    log "Verificando desinstalación completa..."
    
    ISSUES=0
    
    # Verificar servicio
    if systemctl list-unit-files | grep -q "$SERVICE_NAME"; then
        warning "Servicio systemd aún presente"
        ((ISSUES++))
    fi
    
    # Verificar directorio
    if [[ -d "$INSTALL_DIR" ]]; then
        warning "Directorio de instalación aún presente"
        ((ISSUES++))
    fi
    
    # Verificar usuario
    if id "$SERVICE_USER" &>/dev/null; then
        warning "Usuario del servicio aún presente"
        ((ISSUES++))
    fi
    
    # Verificar procesos
    if pgrep -f "wazuh.*reputation" >/dev/null; then
        warning "Procesos relacionados aún ejecutándose"
        ((ISSUES++))
    fi
    
    if [[ $ISSUES -eq 0 ]]; then
        log "Verificación exitosa: Desinstalación completa"
    else
        warning "Se encontraron $ISSUES problemas durante la verificación"
    fi
}

# Mostrar información post-desinstalación
show_post_uninstall_info() {
    echo -e "\n${GREEN}================================${NC}"
    echo -e "${GREEN} DESINSTALACIÓN COMPLETADA${NC}"
    echo -e "${GREEN}================================${NC}\n"
    
    info "El sistema Wazuh IP Reputation ha sido eliminado completamente"
    
    if [[ -n "${BACKUP_DIR:-}" ]]; then
        echo -e "${YELLOW}Backup disponible en: $BACKUP_DIR${NC}"
        echo -e "${YELLOW}Recuerde mover este backup a un lugar seguro${NC}"
    fi
    
    echo -e "\n${BLUE}Elementos eliminados:${NC}"
    echo -e "✓ Servicio systemd"
    echo -e "✓ Directorio de instalación"
    echo -e "✓ Usuario del servicio"
    echo -e "✓ Configuración de cron"
    echo -e "✓ Configuración de logrotate"
    echo -e "✓ Logs del sistema"
    echo -e "✓ Reglas de firewall"
    
    echo -e "\n${YELLOW}Elementos que pueden requerir limpieza manual:${NC}"
    echo -e "- Dependencias Python globales"
    echo -e "- Configuración personalizada de Wazuh"
    echo -e "- Reglas personalizadas de detección"
    
    echo -e "\n${GREEN}Gracias por usar Wazuh IP Reputation Checker${NC}"
}

# Función principal
main() {
    log "Iniciando desinstalación de Wazuh IP Reputation Checker"
    
    check_root
    confirm_uninstall
    offer_backup
    
    stop_service
    remove_systemd_service
    remove_cron_config
    remove_logrotate_config
    remove_logs
    remove_installation_directory
    remove_service_user
    cleanup_firewall
    cleanup_python_dependencies
    
    verify_uninstall
    show_post_uninstall_info
}

# Manejo de errores
trap 'error "Desinstalación fallida en la línea $LINENO"' ERR

# Ejecutar desinstalación
main "$@"
