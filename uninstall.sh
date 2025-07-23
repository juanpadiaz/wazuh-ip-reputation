#!/bin/bash

# =============================================================================
# Wazuh IP Reputation Checker - Script de Desinstalación
# Compatible con: Ubuntu 24.04 LTS
# Versión: 2.0.0
# =============================================================================

set -euo pipefail

# Colores
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly NC='\033[0m'

# Constantes
readonly SERVICE_NAME="wazuh-ip-reputation"
readonly INSTALL_USER="wazuh-reputation"
readonly INSTALL_GROUP="wazuh-reputation"
readonly INSTALL_DIR="/opt/wazuh-ip-reputation"
readonly CONFIG_DIR="/etc/wazuh-ip-reputation"
readonly LOG_DIR="/var/log/wazuh-ip-reputation"
readonly DATA_DIR="/var/lib/wazuh-ip-reputation"
readonly BIN_DIR="/usr/local/bin"
readonly DB_NAME="wazuh_ip_reputation"
readonly DB_USER="wazuh_ip_user"

# Variables
REMOVE_DATA=false
REMOVE_LOGS=false
REMOVE_DB=false
CREATE_BACKUP=true

# Funciones de logging
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

# Banner
show_banner() {
    clear
    echo -e "${RED}"
    cat << "EOF"
 __        __                _       ___ ____  
 \ \      / /_ _ _____   _  | |__   |_ _|  _ \ 
  \ \ /\ / / _` |_  / | | | | '_ \   | || |_) |
   \ V  V / (_| |/ /| |_| | | | | |  | ||  __/ 
    \_/\_/ \__,_/___|\__,_| |_| |_| |___|_|    
                                                
        Reputation Checker - DESINSTALACIÓN
EOF
    echo -e "${NC}"
    echo -e "${RED}Sistema de Análisis de Reputación de IPs para Wazuh${NC}"
    echo
    echo "Este script eliminará:"
    echo "  • Servicio systemd"
    echo "  • Aplicación y scripts"
    echo "  • Usuario y grupo del sistema"
    echo "  • Archivos de configuración"
    echo
    echo "Opciones adicionales:"
    echo "  • Base de datos (opcional)"
    echo "  • Logs del sistema (opcional)"
    echo "  • Datos almacenados (opcional)"
    echo
}

# Verificar root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root"
        exit 1
    fi
}

# Preguntar opciones
ask_options() {
    echo -e "${YELLOW}OPCIONES DE DESINSTALACIÓN:${NC}"
    echo
    
    read -p "¿Crear backup antes de desinstalar? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        CREATE_BACKUP=false
    fi
    
    read -p "¿Eliminar base de datos? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        REMOVE_DB=true
    fi
    
    read -p "¿Eliminar logs? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        REMOVE_LOGS=true
    fi
    
    read -p "¿Eliminar todos los datos almacenados? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        REMOVE_DATA=true
    fi
    
    echo
    echo -e "${YELLOW}RESUMEN DE ACCIONES:${NC}"
    echo "  • Crear backup: $([ "$CREATE_BACKUP" = true ] && echo "SÍ" || echo "NO")"
    echo "  • Eliminar base de datos: $([ "$REMOVE_DB" = true ] && echo "SÍ" || echo "NO")"
    echo "  • Eliminar logs: $([ "$REMOVE_LOGS" = true ] && echo "SÍ" || echo "NO")"
    echo "  • Eliminar datos: $([ "$REMOVE_DATA" = true ] && echo "SÍ" || echo "NO")"
    echo
    
    read -p "¿Confirmar desinstalación? (y/N): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo "Desinstalación cancelada"
        exit 0
    fi
}

# Crear backup
create_backup() {
    if [[ "$CREATE_BACKUP" == "false" ]]; then
        return
    fi
    
    log_info "Creando backup completo..."
    
    BACKUP_DIR="/tmp/wazuh-ip-reputation-backup-$(date +%Y%m%d_%H%M%S)"
    mkdir -p "$BACKUP_DIR"
    
    # Backup de configuración
    if [[ -d "$CONFIG_DIR" ]]; then
        cp -r "$CONFIG_DIR" "$BACKUP_DIR/" 2>/dev/null || true
        log_info "Configuración respaldada"
    fi
    
    # Backup de datos
    if [[ -d "$DATA_DIR" ]]; then
        cp -r "$DATA_DIR" "$BACKUP_DIR/" 2>/dev/null || true
        log_info "Datos respaldados"
    fi
    
    # Backup de logs si no se van a eliminar
    if [[ "$REMOVE_LOGS" == "false" ]] && [[ -d "$LOG_DIR" ]]; then
        cp -r "$LOG_DIR" "$BACKUP_DIR/" 2>/dev/null || true
        log_info "Logs respaldados"
    fi
    
    # Backup de base de datos
    if [[ -f "$CONFIG_DIR/config.ini" ]]; then
        # Extraer credenciales
        DB_HOST=$(grep "^host" "$CONFIG_DIR/config.ini" 2>/dev/null | cut -d'=' -f2 | xargs || echo "localhost")
        DB_PORT=$(grep "^port" "$CONFIG_DIR/config.ini" 2>/dev/null | cut -d'=' -f2 | xargs || echo "3306")
        DB_PASS=$(grep "^password" "$CONFIG_DIR/config.ini" 2>/dev/null | cut -d'=' -f2 | xargs || echo "")
        
        if [[ -n "$DB_PASS" ]]; then
            if mysqldump -h"$DB_HOST" -P"$DB_PORT" -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" > "$BACKUP_DIR/database.sql" 2>/dev/null; then
                log_info "Base de datos respaldada"
            else
                log_warn "No se pudo respaldar la base de datos"
            fi
        fi
    fi
    
    # Comprimir backup
    cd /tmp
    tar czf "$BACKUP_DIR.tar.gz" "$(basename $BACKUP_DIR)" 2>/dev/null || true
    rm -rf "$BACKUP_DIR"
    
    log_info "Backup creado en: $BACKUP_DIR.tar.gz"
    echo -e "${YELLOW}⚠️  IMPORTANTE: Guarde este archivo en un lugar seguro${NC}"
    echo
}

# Detener servicio
stop_service() {
    log_info "Deteniendo servicio..."
    
    if systemctl is-active --quiet $SERVICE_NAME 2>/dev/null; then
        systemctl stop $SERVICE_NAME
        log_info "Servicio detenido"
    fi
    
    if systemctl is-enabled --quiet $SERVICE_NAME 2>/dev/null; then
        systemctl disable $SERVICE_NAME
        log_info "Servicio deshabilitado"
    fi
}

# Eliminar servicio systemd
remove_systemd_service() {
    log_info "Eliminando servicio systemd..."
    
    if [[ -f "/etc/systemd/system/$SERVICE_NAME.service" ]]; then
        rm -f "/etc/systemd/system/$SERVICE_NAME.service"
        systemctl daemon-reload
        log_info "Servicio systemd eliminado"
    fi
}

# Eliminar archivos de la aplicación
remove_application_files() {
    log_info "Eliminando archivos de la aplicación..."
    
    # Eliminar directorio de instalación
    if [[ -d "$INSTALL_DIR" ]]; then
        rm -rf "$INSTALL_DIR"
        log_info "Directorio de aplicación eliminado: $INSTALL_DIR"
    fi
    
    # Eliminar comando global
    if [[ -f "$BIN_DIR/wazuh-reputation" ]]; then
        rm -f "$BIN_DIR/wazuh-reputation"
        log_info "Comando wazuh-reputation eliminado"
    fi
    
    # Eliminar configuración
    if [[ -d "$CONFIG_DIR" ]]; then
        rm -rf "$CONFIG_DIR"
        log_info "Configuración eliminada: $CONFIG_DIR"
    fi
    
    # Eliminar logrotate
    if [[ -f "/etc/logrotate.d/$SERVICE_NAME" ]]; then
        rm -f "/etc/logrotate.d/$SERVICE_NAME"
        log_info "Configuración de logrotate eliminada"
    fi
    
    # Eliminar cron
    if [[ -f "/etc/cron.d/wazuh-ip-reputation-backup" ]]; then
        rm -f "/etc/cron.d/wazuh-ip-reputation-backup"
        log_info "Tarea cron eliminada"
    fi
}

# Eliminar logs
remove_logs() {
    if [[ "$REMOVE_LOGS" == "true" ]]; then
        log_info "Eliminando logs..."
        
        if [[ -d "$LOG_DIR" ]]; then
            rm -rf "$LOG_DIR"
            log_info "Logs eliminados: $LOG_DIR"
        fi
        
        # Eliminar logs de journald
        journalctl --rotate 2>/dev/null || true
        journalctl --vacuum-time=1s 2>/dev/null || true
    else
        log_warn "Logs conservados en: $LOG_DIR"
    fi
}

# Eliminar datos
remove_data() {
    if [[ "$REMOVE_DATA" == "true" ]]; then
        log_info "Eliminando datos almacenados..."
        
        if [[ -d "$DATA_DIR" ]]; then
            rm -rf "$DATA_DIR"
            log_info "Datos eliminados: $DATA_DIR"
        fi
    else
        log_warn "Datos conservados en: $DATA_DIR"
    fi
}

# Eliminar base de datos
remove_database() {
    if [[ "$REMOVE_DB" == "true" ]]; then
        log_info "Eliminando base de datos..."
        
        # Intentar obtener credenciales si existe el archivo de configuración
        DB_PASS=""
        if [[ -f "$CONFIG_DIR/config.ini" ]]; then
            DB_PASS=$(grep "^password" "$CONFIG_DIR/config.ini" 2>/dev/null | cut -d'=' -f2 | xargs || true)
        fi
        
        # Si no tenemos contraseña, intentar con root
        if [[ -z "$DB_PASS" ]]; then
            log_warn "No se encontró contraseña, intentando con usuario root..."
            
            # Verificar si podemos conectar como root
            if mysql -u root -e "SELECT 1;" &>/dev/null; then
                mysql -u root << EOF 2>/dev/null || true
DROP DATABASE IF EXISTS $DB_NAME;
DROP USER IF EXISTS '$DB_USER'@'localhost';
DROP USER IF EXISTS '$DB_USER'@'%';
FLUSH PRIVILEGES;
EOF
                log_info "Base de datos y usuario eliminados"
            else
                log_warn "No se pudo eliminar la base de datos automáticamente"
                echo -e "${YELLOW}Para eliminar manualmente, ejecute:${NC}"
                echo "mysql -u root -p"
                echo "DROP DATABASE IF EXISTS $DB_NAME;"
                echo "DROP USER IF EXISTS '$DB_USER'@'localhost';"
                echo "FLUSH PRIVILEGES;"
            fi
        else
            # Intentar eliminar con las credenciales encontradas
            mysql -u root << EOF 2>/dev/null || true
DROP DATABASE IF EXISTS $DB_NAME;
DROP USER IF EXISTS '$DB_USER'@'localhost';
DROP USER IF EXISTS '$DB_USER'@'%';
FLUSH PRIVILEGES;
EOF
            log_info "Base de datos y usuario eliminados"
        fi
    else
        log_warn "Base de datos conservada: $DB_NAME"
    fi
}

# Eliminar usuario del sistema
remove_system_user() {
    log_info "Eliminando usuario y grupo del sistema..."
    
    # Primero matar cualquier proceso del usuario
    if id "$INSTALL_USER" &>/dev/null; then
        pkill -u "$INSTALL_USER" 2>/dev/null || true
        sleep 2
    fi
    
    # Eliminar usuario
    if id "$INSTALL_USER" &>/dev/null; then
        userdel "$INSTALL_USER" 2>/dev/null || true
        log_info "Usuario $INSTALL_USER eliminado"
    fi
    
    # Eliminar grupo si existe y no tiene otros miembros
    if getent group "$INSTALL_GROUP" >/dev/null 2>&1; then
        # Verificar si hay otros usuarios en el grupo
        GROUP_MEMBERS=$(getent group "$INSTALL_GROUP" | cut -d: -f4)
        if [[ -z "$GROUP_MEMBERS" ]]; then
            groupdel "$INSTALL_GROUP" 2>/dev/null || true
            log_info "Grupo $INSTALL_GROUP eliminado"
        else
            log_warn "Grupo $INSTALL_GROUP tiene otros miembros, no se eliminó"
        fi
    fi
}

# Limpiar Python cache
cleanup_python_cache() {
    log_info "Limpiando cache de Python..."
    
    # Buscar y eliminar archivos relacionados
    find /usr/local/lib -name "*wazuh*reputation*" -type d -exec rm -rf {} + 2>/dev/null || true
    find /usr/local/lib -name "*wazuh*ip*" -type d -exec rm -rf {} + 2>/dev/null || true
    find /root/.cache -name "*wazuh*reputation*" -type d -exec rm -rf {} + 2>/dev/null || true
    find /home -name "*wazuh*reputation*" -type d -exec rm -rf {} + 2>/dev/null || true
    
    # Limpiar pip cache
    pip3 cache purge 2>/dev/null || true
}

# Verificar y limpiar restos
cleanup_remnants() {
    log_info "Verificando y limpiando posibles restos..."
    
    # Buscar archivos o directorios huérfanos
    local remnants=0
    
    # Verificar directorios
    for dir in "$INSTALL_DIR" "$CONFIG_DIR" "$LOG_DIR" "$DATA_DIR"; do
        if [[ -d "$dir" ]]; then
            log_warn "Directorio remanente encontrado: $dir"
            ((remnants++))
        fi
    done
    
    # Verificar archivos
    if [[ -f "$BIN_DIR/wazuh-reputation" ]]; then
        log_warn "Archivo remanente encontrado: $BIN_DIR/wazuh-reputation"
        ((remnants++))
    fi
    
    # Verificar servicio
    if systemctl list-unit-files | grep -q "$SERVICE_NAME"; then
        log_warn "Servicio remanente encontrado: $SERVICE_NAME"
        ((remnants++))
    fi
    
    if [[ $remnants -eq 0 ]]; then
        log_info "No se encontraron restos del sistema"
    else
        log_warn "Se encontraron $remnants elementos remanentes"
    fi
}

# Mostrar resumen
show_summary() {
    echo
    echo -e "${GREEN}================================================${NC}"
    echo -e "${GREEN}  DESINSTALACIÓN COMPLETADA${NC}"
    echo -e "${GREEN}================================================${NC}"
    echo
    
    echo "✅ Eliminado:"
    echo "   • Servicio systemd"
    echo "   • Aplicación y scripts"
    echo "   • Usuario y grupo del sistema"
    echo "   • Archivos de configuración"
    echo "   • Tareas programadas (cron)"
    echo "   • Configuración de logrotate"
    
    if [[ "$REMOVE_DB" == "true" ]]; then
        echo "   • Base de datos y usuario MySQL/MariaDB"
    fi
    
    if [[ "$REMOVE_LOGS" == "true" ]]; then
        echo "   • Logs del sistema"
    fi
    
    if [[ "$REMOVE_DATA" == "true" ]]; then
        echo "   • Datos almacenados"
    fi
    
    echo
    
    if [[ "$CREATE_BACKUP" == "true" ]]; then
        echo -e "${YELLOW}📁 Backup guardado en: $BACKUP_DIR.tar.gz${NC}"
        echo -e "${YELLOW}   ⚠️  Guarde este archivo en un lugar seguro${NC}"
        echo
    fi
    
    if [[ "$REMOVE_DB" == "false" ]] || [[ "$REMOVE_LOGS" == "false" ]] || [[ "$REMOVE_DATA" == "false" ]]; then
        echo -e "${YELLOW}⚠️  Algunos componentes no fueron eliminados:${NC}"
        
        if [[ "$REMOVE_DB" == "false" ]]; then
            echo "   • Base de datos: $DB_NAME"
            echo "   • Usuario MySQL: $DB_USER"
        fi
        
        if [[ "$REMOVE_LOGS" == "false" ]]; then
            echo "   • Logs en: $LOG_DIR"
        fi
        
        if [[ "$REMOVE_DATA" == "false" ]]; then
            echo "   • Datos en: $DATA_DIR"
        fi
        
        echo
        echo "Para eliminar manualmente estos componentes más tarde:"
        echo "   • Base de datos: mysql -u root -p -e \"DROP DATABASE $DB_NAME; DROP USER '$DB_USER'@'localhost';\""
        echo "   • Logs: sudo rm -rf $LOG_DIR"
        echo "   • Datos: sudo rm -rf $DATA_DIR"
        echo
    fi
    
    echo -e "${GREEN}Wazuh IP Reputation Checker ha sido desinstalado${NC}"
    echo
    echo "Si desea reinstalar el sistema en el futuro:"
    echo "   wget https://raw.githubusercontent.com/your-repo/wazuh-ip-reputation/main/install.sh"
    echo "   sudo bash install.sh"
    echo
    echo "¡Gracias por usar Wazuh IP Reputation Checker!"
}

# Función principal
main() {
    show_banner
    check_root
    ask_options
    
    echo
    log_info "Iniciando desinstalación..."
    echo
    
    # Proceso de desinstalación
    create_backup
    stop_service
    remove_systemd_service
    remove_application_files
    remove_logs
    remove_data
    remove_database
    remove_system_user
    cleanup_python_cache
    cleanup_remnants
    
    show_summary
}

# Manejo de errores
error_handler() {
    local exit_code=$?
    echo
    log_error "Error durante la desinstalación (código: $exit_code)"
    echo -e "${YELLOW}Es posible que algunos componentes no se hayan eliminado correctamente${NC}"
    echo -e "${YELLOW}Verifique manualmente y elimine los componentes restantes si es necesario${NC}"
    exit $exit_code
}

trap error_handler ERR

# Ejecutar
main "$@"