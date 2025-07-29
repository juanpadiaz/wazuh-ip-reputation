#!/bin/bash

# =============================================================================
# Wazuh IP Reputation Checker - Script de Desinstalación
# Compatible con: Ubuntu 24.04 LTS
# Versión: 3.0.0
# https://github.com/juanpadiaz/
# =============================================================================

set -euo pipefail

# Colores para output
readonly RED='\033[0;31m'
readonly GREEN='\033[0;32m'
readonly YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m'
readonly PURPLE='\033[0;35m'
readonly CYAN='\033[0;36m'
readonly NC='\033[0m'

# Constantes del sistema
readonly SCRIPT_VERSION="3.0.0"
readonly INSTALL_USER="wazuh-reputation"
readonly INSTALL_GROUP="wazuh-reputation"
readonly INSTALL_DIR="/opt/wazuh-ip-reputation"
readonly CONFIG_DIR="/etc/wazuh-ip-reputation"
readonly LOG_DIR="/var/log/wazuh-ip-reputation"
readonly DATA_DIR="/var/lib/wazuh-ip-reputation"
readonly BIN_DIR="/usr/local/bin"
readonly SERVICE_NAME="wazuh-ip-reputation"
readonly BACKUP_DIR="/var/lib/wazuh-ip-reputation/backups"

# Variables globales
FORCE_MODE=false
CREATE_BACKUP=true
REMOVE_DATABASE=true
DB_NAME=""
DB_USER=""
DB_PASSWORD=""
DB_HOST=""
DB_TYPE=""
MARIADB_WAS_INSTALLED=false

# Funciones de logging
log_header() {
    echo -e "\n${BLUE}================================================================${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}================================================================${NC}\n"
}

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_step() {
    echo -e "\n${CYAN}[STEP]${NC} $1"
}

# Banner de desinstalación
show_uninstall_banner() {
    clear
    echo -e "${RED}"
    cat << "EOF"
 _   _ _   _ ___ _   _ ____ _____  _    _     _     
| | | | \ | |_ _| \ | / ___|_   _|/ \  | |   | |    
| | | |  \| || ||  \| \___ \ | | / _ \ | |   | |    
| |_| | |\  || || |\  |___) || |/ ___ \| |___| |___ 
 \___/|_| \_|___|_| \_|____/ |_/_/   \_\_____|_____|
                                                     
   Wazuh IP Reputation Checker - Desinstalación
EOF
    echo -e "${NC}"
    echo -e "${YELLOW}⚠️  ADVERTENCIA: Este proceso eliminará:${NC}"
    echo "   • Servicio systemd"
    echo "   • Aplicación y archivos de configuración"
    echo "   • Usuario y grupo del sistema"
    echo "   • Base de datos y tablas (opcional)"
    echo "   • Logs y datos almacenados"
    echo
    echo -e "${CYAN}Se le preguntará antes de eliminar componentes críticos${NC}"
    echo
}

# Verificar prerrequisitos
check_prerequisites() {
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root (sudo)"
        exit 1
    fi
    
    if [[ ! -d "$INSTALL_DIR" ]] && [[ ! -f "/etc/systemd/system/$SERVICE_NAME.service" ]]; then
        log_error "No se encontró instalación de Wazuh IP Reputation Checker"
        exit 1
    fi
}

# Parsear argumentos
parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --force|-f)
                FORCE_MODE=true
                shift
                ;;
            --no-backup)
                CREATE_BACKUP=false
                shift
                ;;
            --keep-database)
                REMOVE_DATABASE=false
                shift
                ;;
            --help|-h)
                show_help
                exit 0
                ;;
            *)
                log_error "Opción desconocida: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# Mostrar ayuda
show_help() {
    echo "Uso: $0 [opciones]"
    echo
    echo "Opciones:"
    echo "  --force, -f        No pedir confirmación para cada paso"
    echo "  --no-backup        No crear backup de la base de datos"
    echo "  --keep-database    Mantener la base de datos"
    echo "  --help, -h         Mostrar esta ayuda"
    echo
    echo "Ejemplo:"
    echo "  $0                 # Desinstalación interactiva completa"
    echo "  $0 --force         # Desinstalación sin confirmaciones"
    echo "  $0 --keep-database # Desinstalar pero mantener base de datos"
}

# Confirmar acción
confirm_action() {
    local message="$1"
    local default="${2:-n}"
    
    if [[ "$FORCE_MODE" == "true" ]]; then
        return 0
    fi
    
    if [[ "$default" == "y" ]]; then
        read -p "$message (Y/n): " -n 1 -r
        echo
        [[ $REPLY =~ ^[Nn]$ ]] && return 1 || return 0
    else
        read -p "$message (y/N): " -n 1 -r
        echo
        [[ $REPLY =~ ^[Yy]$ ]] && return 0 || return 1
    fi
}

# Detener servicio
stop_service() {
    log_step "Deteniendo servicio..."
    
    if systemctl is-active --quiet $SERVICE_NAME; then
        systemctl stop $SERVICE_NAME
        log_success "Servicio detenido"
    else
        log_info "El servicio no estaba activo"
    fi
    
    if systemctl is-enabled --quiet $SERVICE_NAME 2>/dev/null; then
        systemctl disable $SERVICE_NAME
        log_success "Servicio deshabilitado"
    fi
}

# Leer configuración de base de datos
read_database_config() {
    local config_file="$CONFIG_DIR/config.ini"
    
    if [[ -f "$config_file" ]]; then
        log_info "Leyendo configuración de base de datos..."
        
        DB_HOST=$(grep "^host" "$config_file" 2>/dev/null | cut -d'=' -f2 | xargs) || DB_HOST="localhost"
        DB_NAME=$(grep "^database" "$config_file" 2>/dev/null | cut -d'=' -f2 | xargs) || DB_NAME=""
        DB_USER=$(grep "^user" "$config_file" 2>/dev/null | cut -d'=' -f2 | xargs) || DB_USER=""
        DB_PASSWORD=$(grep "^password" "$config_file" 2>/dev/null | cut -d'=' -f2 | xargs) || DB_PASSWORD=""
        
        # Detectar tipo de base de datos
        if command -v mysql &>/dev/null && mysql --version 2>&1 | grep -qi mariadb; then
            DB_TYPE="mariadb"
        else
            DB_TYPE="mysql"
        fi
        
        if [[ -n "$DB_NAME" ]]; then
            log_info "Base de datos encontrada: $DB_NAME en $DB_HOST"
        fi
    else
        log_warn "No se encontró archivo de configuración"
    fi
}

# Verificar si MariaDB fue instalado por nosotros
check_mariadb_installation() {
    # Verificar si existe un archivo de marca que indique que instalamos MariaDB
    local marker_file="/var/lib/wazuh-ip-reputation/.mariadb_installed"
    
    if [[ -f "$marker_file" ]]; then
        MARIADB_WAS_INSTALLED=true
        log_info "MariaDB fue instalado como parte de Wazuh IP Reputation"
    else
        # Verificar si MariaDB está instalado pero no por nosotros
        if command -v mariadb &>/dev/null || command -v mysql &>/dev/null; then
            log_info "MariaDB/MySQL detectado pero instalado previamente"
        fi
    fi
}

# Crear backup de base de datos
create_database_backup() {
    if [[ "$CREATE_BACKUP" != "true" ]] || [[ -z "$DB_NAME" ]]; then
        return
    fi
    
    log_step "Creando backup de base de datos..."
    
    local timestamp=$(date +%Y%m%d_%H%M%S)
    local backup_file="$BACKUP_DIR/uninstall_backup_${timestamp}.sql"
    
    mkdir -p "$BACKUP_DIR"
    
    if mysqldump -u"$DB_USER" -p"$DB_PASSWORD" -h"$DB_HOST" "$DB_NAME" > "$backup_file" 2>/dev/null; then
        gzip "$backup_file"
        log_success "Backup creado: ${backup_file}.gz"
        echo -e "${CYAN}Guarde este archivo en un lugar seguro antes de continuar${NC}"
        
        # Dar tiempo para que el usuario tome nota
        if [[ "$FORCE_MODE" != "true" ]]; then
            read -p "Presione Enter para continuar..."
        fi
    else
        log_error "No se pudo crear el backup de la base de datos"
        if ! confirm_action "¿Continuar sin backup?" "n"; then
            log_info "Desinstalación cancelada"
            exit 1
        fi
    fi
}

# Eliminar base de datos
remove_database() {
    if [[ "$REMOVE_DATABASE" != "true" ]] || [[ -z "$DB_NAME" ]]; then
        return
    fi
    
    log_step "Eliminando base de datos..."
    
    if confirm_action "¿Eliminar base de datos '$DB_NAME' y usuario '$DB_USER'?" "n"; then
        # Crear script SQL temporal
        cat > /tmp/uninstall_db.sql << EOF
-- Eliminar base de datos
DROP DATABASE IF EXISTS $DB_NAME;

-- Eliminar usuario
DROP USER IF EXISTS '$DB_USER'@'$DB_HOST';
DROP USER IF EXISTS '$DB_USER'@'localhost';
DROP USER IF EXISTS '$DB_USER'@'%';

-- Aplicar cambios
FLUSH PRIVILEGES;
EOF
        
        if mysql -u root < /tmp/uninstall_db.sql 2>/dev/null; then
            log_success "Base de datos y usuario eliminados"
        else
            log_error "Error eliminando base de datos (puede requerir contraseña root de MySQL)"
            echo "Intente ejecutar manualmente:"
            echo "  mysql -u root -p < /tmp/uninstall_db.sql"
        fi
        
        rm -f /tmp/uninstall_db.sql
    else
        log_info "Base de datos conservada"
    fi
}

# Eliminar archivos del sistema
remove_system_files() {
    log_step "Eliminando archivos del sistema..."
    
    # Lista de archivos y directorios a eliminar
    local items_to_remove=(
        "/etc/systemd/system/$SERVICE_NAME.service"
        "/etc/logrotate.d/$SERVICE_NAME"
        "/etc/cron.d/wazuh-ip-reputation-backup"
        "$BIN_DIR/wazuh-reputation"
        "$INSTALL_DIR"
        "$CONFIG_DIR"
        "$LOG_DIR"
        "$DATA_DIR"
    )
    
    for item in "${items_to_remove[@]}"; do
        if [[ -e "$item" ]]; then
            if [[ -d "$item" ]]; then
                log_info "Eliminando directorio: $item"
                rm -rf "$item"
            else
                log_info "Eliminando archivo: $item"
                rm -f "$item"
            fi
        fi
    done
    
    # Recargar systemd
    systemctl daemon-reload
    
    log_success "Archivos del sistema eliminados"
}

# Eliminar usuario y grupo
remove_user_and_group() {
    log_step "Eliminando usuario y grupo del sistema..."
    
    # Eliminar usuario
    if id "$INSTALL_USER" &>/dev/null; then
        if confirm_action "¿Eliminar usuario del sistema '$INSTALL_USER'?" "y"; then
            userdel "$INSTALL_USER" 2>/dev/null || true
            log_success "Usuario eliminado"
        fi
    fi
    
    # Eliminar grupo
    if getent group "$INSTALL_GROUP" >/dev/null 2>&1; then
        if confirm_action "¿Eliminar grupo del sistema '$INSTALL_GROUP'?" "y"; then
            groupdel "$INSTALL_GROUP" 2>/dev/null || true
            log_success "Grupo eliminado"
        fi
    fi
}

# Limpiar paquetes Python
cleanup_python_packages() {
    log_step "Limpiando entorno Python..."
    
    # Si el directorio venv existe, ya fue eliminado con INSTALL_DIR
    # Solo informamos que se limpió
    log_info "Entorno virtual Python eliminado"
}

# Verificar si quedan archivos
check_remaining_files() {
    log_step "Verificando archivos remanentes..."
    
    local remaining_files=()
    local check_paths=(
        "/etc/wazuh-ip-reputation"
        "/var/log/wazuh-ip-reputation"
        "/var/lib/wazuh-ip-reputation"
        "/opt/wazuh-ip-reputation"
    )
    
    for path in "${check_paths[@]}"; do
        if [[ -e "$path" ]]; then
            remaining_files+=("$path")
        fi
    done
    
    if [[ ${#remaining_files[@]} -gt 0 ]]; then
        log_warn "Se encontraron archivos remanentes:"
        for file in "${remaining_files[@]}"; do
            echo "  - $file"
        done
        
        if confirm_action "¿Eliminar estos archivos?" "y"; then
            for file in "${remaining_files[@]}"; do
                rm -rf "$file"
            done
            log_success "Archivos remanentes eliminados"
        fi
    else
        log_success "No se encontraron archivos remanentes"
    fi
}

# Mostrar resumen final
show_summary() {
    log_header "DESINSTALACIÓN COMPLETADA"
    
    echo -e "${GREEN}✅ Wazuh IP Reputation Checker ha sido desinstalado${NC}"
    echo
    
    echo "📋 COMPONENTES ELIMINADOS:"
    echo "   ✓ Servicio systemd"
    echo "   ✓ Aplicación y scripts"
    echo "   ✓ Archivos de configuración"
    echo "   ✓ Logs y datos temporales"
    
    if [[ "$REMOVE_DATABASE" == "true" ]]; then
        echo "   ✓ Base de datos y tablas"
    else
        echo "   ⚠️  Base de datos conservada"
    fi
    
    echo
    
    if [[ "$CREATE_BACKUP" == "true" ]] && [[ -d "$BACKUP_DIR" ]]; then
        echo "💾 BACKUPS DISPONIBLES:"
        echo "   Ubicación: $BACKUP_DIR"
        ls -la "$BACKUP_DIR"/*.gz 2>/dev/null | tail -5 || echo "   No se encontraron backups"
        echo
    fi
    
    if [[ "$REMOVE_DATABASE" != "true" ]]; then
        echo -e "${YELLOW}⚠️  NOTA: La base de datos no fue eliminada${NC}"
        echo "   Para eliminarla manualmente:"
        echo "   mysql -u root -p -e \"DROP DATABASE IF EXISTS $DB_NAME; DROP USER IF EXISTS '$DB_USER'@'$DB_HOST';\""
        echo
    fi
    
    if [[ "$MARIADB_WAS_INSTALLED" == "true" ]]; then
        echo -e "${CYAN}ℹ️  MariaDB fue instalado con este sistema${NC}"
        echo "   Si desea desinstalarlo también:"
        echo "   sudo apt-get remove --purge mariadb-server mariadb-client"
        echo "   sudo apt-get autoremove"
        echo
    fi
    
    echo -e "${GREEN}¡Gracias por usar Wazuh IP Reputation Checker!${NC}"
}

# Función principal
main() {
    # Parsear argumentos
    parse_arguments "$@"
    
    # Mostrar banner
    show_uninstall_banner
    
    # Verificar prerrequisitos
    check_prerequisites
    
    # Confirmar desinstalación
    if ! confirm_action "¿Está seguro de que desea desinstalar Wazuh IP Reputation Checker?" "n"; then
        log_info "Desinstalación cancelada"
        exit 0
    fi
    
    # Leer configuración
    read_database_config
    
    # Verificar si instalamos MariaDB
    check_mariadb_installation
    
    # Detener servicio
    stop_service
    
    # Crear backup si está configurado
    if [[ "$CREATE_BACKUP" == "true" ]] && [[ -n "$DB_NAME" ]]; then
        create_database_backup
    fi
    
    # Eliminar base de datos si está configurado
    if [[ "$REMOVE_DATABASE" == "true" ]] && [[ -n "$DB_NAME" ]]; then
        remove_database
    fi
    
    # Eliminar archivos del sistema
    remove_system_files
    
    # Eliminar usuario y grupo
    remove_user_and_group
    
    # Limpiar paquetes Python
    cleanup_python_packages
    
    # Verificar archivos remanentes
    check_remaining_files
    
    # Mostrar resumen
    show_summary
}

# Ejecutar desinstalación
main "$@"
