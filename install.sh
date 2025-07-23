#!/bin/bash

# =============================================================================
# Wazuh IP Reputation Checker - Script de Instalación
# Compatible con: Ubuntu 24.04 LTS
# Versión: 2.0.0
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
readonly SCRIPT_VERSION="2.0.0"
readonly INSTALL_USER="wazuh-reputation"
readonly INSTALL_GROUP="wazuh-reputation"
readonly INSTALL_DIR="/opt/wazuh-ip-reputation"
readonly CONFIG_DIR="/etc/wazuh-ip-reputation"
readonly LOG_DIR="/var/log/wazuh-ip-reputation"
readonly DATA_DIR="/var/lib/wazuh-ip-reputation"
readonly BIN_DIR="/usr/local/bin"
readonly SERVICE_NAME="wazuh-ip-reputation"

# Variables globales
DB_TYPE=""
DB_HOST="localhost"
DB_PORT="3306"
DB_NAME="wazuh_ip_reputation"
DB_USER="wazuh_ip_user"
DB_PASSWORD=""
WAZUH_HOST=""
WAZUH_PORT="55000"
WAZUH_USERNAME=""
WAZUH_PASSWORD=""
VIRUSTOTAL_API_KEY=""
ABUSEIPDB_API_KEY=""
SHODAN_API_KEY=""
SMTP_SERVER=""
SMTP_PORT=""
SENDER_EMAIL=""
SENDER_PASSWORD=""
RECIPIENT_EMAILS=""
CHECK_INTERVAL="300"
CURRENT_USER="${SUDO_USER:-$USER}"

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

# Función de limpieza
cleanup() {
    echo -e "\n${YELLOW}[CLEANUP]${NC} Limpiando archivos temporales..."
    rm -f /tmp/wazuh-ip-*.tmp /tmp/db_setup.sql 2>/dev/null || true
}
trap cleanup EXIT

# Banner de bienvenida
show_welcome_banner() {
    clear
    echo -e "${BLUE}"
    cat << "EOF"
 __        __                _       ___ ____  
 \ \      / /_ _ _____   _  | |__   |_ _|  _ \ 
  \ \ /\ / / _` |_  / | | | | '_ \   | || |_) |
   \ V  V / (_| |/ /| |_| | | | | |  | ||  __/ 
    \_/\_/ \__,_/___|\__,_| |_| |_| |___|_|    
                                                
        Reputation Checker v2.0.0
EOF
    echo -e "${NC}"
    echo -e "${GREEN}Sistema de Análisis de Reputación de IPs para Wazuh${NC}"
    echo
    echo "🎯 Este instalador configurará:"
    echo "   ✅ Base de datos MariaDB/MySQL"
    echo "   ✅ Integración con Wazuh API"
    echo "   ✅ APIs: VirusTotal, AbuseIPDB, Shodan"
    echo "   ✅ Sistema de notificaciones por email"
    echo "   ✅ Servicio systemd con monitoreo automático"
    echo "   ✅ Herramientas de administración"
    echo
    read -p "🚀 ¿Continuar con la instalación? (Y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Nn]$ ]]; then
        echo "Instalación cancelada."
        exit 0
    fi
}

# Generar contraseña segura
generate_password() {
    openssl rand -base64 16 | tr -d "=+/" | cut -c1-16
}

# Validar email
validate_email() {
    local email="$1"
    if [[ $email =~ ^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$ ]]; then
        return 0
    else
        return 1
    fi
}

# Verificar prerrequisitos
check_prerequisites() {
    log_step "Verificando prerrequisitos..."
    
    if [[ $EUID -ne 0 ]]; then
        log_error "Este script debe ejecutarse como root (sudo)"
        exit 1
    fi
    
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 no está instalado"
        exit 1
    fi
    
    if ! timeout 5 ping -c 1 8.8.8.8 &> /dev/null; then
        log_error "Sin conectividad a internet"
        exit 1
    fi
    
    # Verificar versión de Ubuntu
    if command -v lsb_release &> /dev/null; then
        local ubuntu_version=$(lsb_release -rs)
        log_info "Ubuntu versión: $ubuntu_version"
    fi
    
    log_success "Prerrequisitos verificados"
}

# Instalar dependencias
install_dependencies() {
    log_step "Instalando dependencias del sistema..."
    
    apt-get update -qq
    
    # Paquetes básicos
    local packages=(
        "python3-pip" "python3-venv" "python3-dev" 
        "build-essential" "curl" "wget" "git" 
        "logrotate" "systemd" "jq"
    )
    
    # Verificar si necesitamos instalar base de datos
    if ! command -v mysql &>/dev/null && ! command -v mariadb &>/dev/null; then
        packages+=("mariadb-server" "mariadb-client")
        DB_TYPE="mariadb"
    else
        if mysql --version 2>&1 | grep -qi mariadb; then
            DB_TYPE="mariadb"
        else
            DB_TYPE="mysql"
        fi
    fi
    
    DEBIAN_FRONTEND=noninteractive apt-get install -y "${packages[@]}"
    
    if [[ "$DB_TYPE" == "mariadb" ]] && ! systemctl is-active --quiet mariadb; then
        systemctl enable mariadb
        systemctl start mariadb
    fi
    
    log_success "Dependencias instaladas"
}

# Crear usuario y grupo del sistema
create_system_user() {
    log_step "Creando usuario y grupo del sistema..."
    
    # Crear grupo
    if ! getent group "$INSTALL_GROUP" >/dev/null 2>&1; then
        groupadd -r "$INSTALL_GROUP"
        log_info "Grupo $INSTALL_GROUP creado"
    fi
    
    # Crear usuario
    if ! id "$INSTALL_USER" &>/dev/null; then
        useradd -r -s /bin/false -d "$INSTALL_DIR" -g "$INSTALL_GROUP" -c "Wazuh IP Reputation Service" "$INSTALL_USER"
        log_info "Usuario $INSTALL_USER creado"
    fi
    
    # Agregar usuario actual al grupo para facilitar administración
    if [ -n "$CURRENT_USER" ] && [ "$CURRENT_USER" != "root" ]; then
        usermod -a -G "$INSTALL_GROUP" "$CURRENT_USER"
        log_info "Usuario $CURRENT_USER agregado al grupo $INSTALL_GROUP"
    fi
    
    log_success "Usuario y grupo configurados"
}

# Crear estructura de directorios
create_directories() {
    log_step "Creando estructura de directorios..."
    
    local directories=(
        "$INSTALL_DIR"
        "$CONFIG_DIR"
        "$LOG_DIR"
        "$DATA_DIR"
        "$DATA_DIR/cache"
        "$DATA_DIR/scripts"
        "$DATA_DIR/backups"
    )
    
    for dir in "${directories[@]}"; do
        mkdir -p "$dir"
        case "$dir" in
            "$CONFIG_DIR")
                chown root:"$INSTALL_GROUP" "$dir"
                chmod 750 "$dir"
                ;;
            "$LOG_DIR"|"$DATA_DIR"|"$DATA_DIR/"*)
                chown "$INSTALL_USER:$INSTALL_GROUP" "$dir"
                chmod 755 "$dir"
                ;;
            *)
                chown "$INSTALL_USER:$INSTALL_GROUP" "$dir"
                chmod 755 "$dir"
                ;;
        esac
    done
    
    log_success "Directorios creados"
}

# Configurar entorno Python
setup_python_environment() {
    log_step "Configurando entorno Python..."
    
    cd "$INSTALL_DIR"
    
    # Crear entorno virtual
    sudo -u "$INSTALL_USER" python3 -m venv venv
    
    # Crear requirements.txt
    cat > requirements.txt << 'EOF'
requests>=2.31.0
mysql-connector-python>=8.0.33
schedule>=1.2.0
configparser>=6.0.0
python-dateutil>=2.8.2
tabulate>=0.9.0
colorama>=0.4.6
shodan>=1.31.0
validators>=0.22.0
EOF
    
    # Instalar dependencias
    sudo -u "$INSTALL_USER" bash -c "
        source venv/bin/activate
        pip install --upgrade pip wheel setuptools
        pip install -r requirements.txt
    "
    
    chown -R "$INSTALL_USER:$INSTALL_GROUP" "$INSTALL_DIR"
    log_success "Entorno Python configurado"
}

# Configurar base de datos
setup_database() {
    log_step "Configurando base de datos $DB_TYPE..."
    
    DB_PASSWORD=$(generate_password)
    
    # Crear script SQL temporal
    cat > /tmp/db_setup.sql << SQLEOF
-- Eliminar usuario existente si existe
DROP USER IF EXISTS '$DB_USER'@'$DB_HOST';

-- Crear base de datos
CREATE DATABASE IF NOT EXISTS $DB_NAME CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- Crear usuario
CREATE USER '$DB_USER'@'$DB_HOST' IDENTIFIED BY '$DB_PASSWORD';

-- Otorgar permisos
GRANT ALL PRIVILEGES ON $DB_NAME.* TO '$DB_USER'@'$DB_HOST';
FLUSH PRIVILEGES;

-- Usar la base de datos
USE $DB_NAME;

-- Tabla principal de reputación de IPs
CREATE TABLE IF NOT EXISTS ip_reputation (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    -- VirusTotal
    vt_detections INT DEFAULT 0,
    vt_total_engines INT DEFAULT 0,
    vt_malicious_votes INT DEFAULT 0,
    vt_suspicious_votes INT DEFAULT 0,
    -- AbuseIPDB
    abuse_confidence_score INT DEFAULT 0,
    abuse_usage_type VARCHAR(100),
    abuse_isp VARCHAR(255),
    abuse_country_code VARCHAR(10),
    abuse_is_whitelisted BOOLEAN DEFAULT FALSE,
    -- Shodan
    shodan_ports TEXT,
    shodan_vulns TEXT,
    shodan_tags TEXT,
    shodan_os VARCHAR(100),
    shodan_org VARCHAR(255),
    -- Clasificación general
    risk_score INT DEFAULT 0,
    risk_level ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'SAFE') DEFAULT 'LOW',
    is_malicious BOOLEAN DEFAULT FALSE,
    is_suspicious BOOLEAN DEFAULT FALSE,
    -- Metadatos
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_checked DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    last_alert_sent DATETIME,
    check_count INT DEFAULT 1,
    -- Índices
    INDEX idx_ip (ip_address),
    INDEX idx_risk_level (risk_level),
    INDEX idx_last_checked (last_checked),
    INDEX idx_malicious (is_malicious)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla de IPs procesadas de Wazuh
CREATE TABLE IF NOT EXISTS processed_ips (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    source_alert_id VARCHAR(100),
    source_agent_id VARCHAR(100),
    source_agent_name VARCHAR(255),
    source_rule_id VARCHAR(50),
    source_rule_description TEXT,
    processed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_processed_at (processed_at),
    INDEX idx_ip_address (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla de alertas enviadas
CREATE TABLE IF NOT EXISTS sent_alerts (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    alert_type ENUM('EMAIL', 'WAZUH', 'WEBHOOK') DEFAULT 'EMAIL',
    alert_level VARCHAR(20),
    recipients TEXT,
    subject VARCHAR(255),
    content TEXT,
    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    status ENUM('SENT', 'FAILED', 'PENDING') DEFAULT 'SENT',
    error_message TEXT,
    INDEX idx_sent_at (sent_at),
    INDEX idx_ip_address (ip_address)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla de estadísticas del sistema
CREATE TABLE IF NOT EXISTS system_stats (
    id INT AUTO_INCREMENT PRIMARY KEY,
    stat_date DATE NOT NULL UNIQUE,
    total_ips_checked INT DEFAULT 0,
    malicious_ips_found INT DEFAULT 0,
    suspicious_ips_found INT DEFAULT 0,
    alerts_sent INT DEFAULT 0,
    api_calls_virustotal INT DEFAULT 0,
    api_calls_abuseipdb INT DEFAULT 0,
    api_calls_shodan INT DEFAULT 0,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_stat_date (stat_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Tabla de configuración del sistema
CREATE TABLE IF NOT EXISTS system_config (
    config_key VARCHAR(100) PRIMARY KEY,
    config_value TEXT,
    description TEXT,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Insertar configuración inicial
INSERT INTO system_config (config_key, config_value, description) VALUES
('installation_date', NOW(), 'Fecha de instalación del sistema'),
('database_version', '2.0.0', 'Versión del esquema de base de datos'),
('last_wazuh_check', NULL, 'Última verificación de alertas de Wazuh'),
('total_ips_analyzed', '0', 'Total de IPs analizadas');
SQLEOF
    
    # Ejecutar script SQL
    if [[ "$DB_TYPE" == "mariadb" ]] || [[ "$DB_TYPE" == "mysql" ]]; then
        mysql -u root < /tmp/db_setup.sql || {
            log_error "Error configurando base de datos"
            rm -f /tmp/db_setup.sql
            exit 1
        }
    fi
    
    rm -f /tmp/db_setup.sql
    
    # Verificar conexión
    if mysql -u "$DB_USER" -p"$DB_PASSWORD" "$DB_NAME" -e "SELECT 1;" &>/dev/null; then
        log_success "Base de datos configurada correctamente"
    else
        log_error "Error verificando conexión a base de datos"
        exit 1
    fi
}

# Configurar Wazuh
configure_wazuh() {
    log_header "CONFIGURACIÓN DE WAZUH"
    
    echo "📡 Conexión con Wazuh Manager"
    echo
    
    read -p "Host/IP del Wazuh Manager [localhost]: " wazuh_input
    WAZUH_HOST=${wazuh_input:-localhost}
    
    read -p "Puerto de la API de Wazuh [55000]: " port_input
    WAZUH_PORT=${port_input:-55000}
    
    read -p "Usuario de la API de Wazuh: " WAZUH_USERNAME
    while [[ -z "$WAZUH_USERNAME" ]]; do
        echo "❌ El usuario es requerido"
        read -p "Usuario de la API de Wazuh: " WAZUH_USERNAME
    done
    
    read -s -p "Contraseña de la API de Wazuh: " WAZUH_PASSWORD
    echo
    while [[ -z "$WAZUH_PASSWORD" ]]; do
        echo "❌ La contraseña es requerida"
        read -s -p "Contraseña de la API de Wazuh: " WAZUH_PASSWORD
        echo
    done
    
    log_success "Configuración de Wazuh completada"
}

# Configurar APIs de reputación
configure_reputation_apis() {
    log_header "CONFIGURACIÓN DE APIs DE REPUTACIÓN"
    
    # VirusTotal
    echo "🔍 VirusTotal API"
    echo "   Obtener en: https://www.virustotal.com/gui/my-apikey"
    read -p "API Key de VirusTotal: " VIRUSTOTAL_API_KEY
    
    # AbuseIPDB
    echo
    echo "🛡️ AbuseIPDB API"
    echo "   Obtener en: https://www.abuseipdb.com/account/api"
    read -p "API Key de AbuseIPDB: " ABUSEIPDB_API_KEY
    
    # Shodan
    echo
    echo "🌐 Shodan API"
    echo "   Obtener en: https://account.shodan.io/"
    read -p "API Key de Shodan (opcional): " SHODAN_API_KEY
    
    if [[ -z "$VIRUSTOTAL_API_KEY" ]] && [[ -z "$ABUSEIPDB_API_KEY" ]]; then
        log_warn "⚠️ Se recomienda configurar al menos una API de reputación"
    else
        log_success "APIs de reputación configuradas"
    fi
}

# Configurar email
configure_email() {
    log_header "CONFIGURACIÓN DE NOTIFICACIONES POR EMAIL"
    
    read -p "¿Configurar notificaciones por email? (y/N): " configure_mail
    if [[ ! $configure_mail =~ ^[Yy]$ ]]; then
        log_info "Notificaciones por email omitidas"
        return
    fi
    
    # Servidor SMTP
    echo
    echo "📮 SERVIDORES SMTP COMUNES:"
    echo "  • Gmail: smtp.gmail.com:587"
    echo "  • Outlook: smtp-mail.outlook.com:587"
    echo "  • Yahoo: smtp.mail.yahoo.com:587"
    echo "  • Office 365: smtp.office365.com:587"
    echo
    
    read -p "Servidor SMTP: " SMTP_SERVER
    read -p "Puerto SMTP [587]: " smtp_port_input
    SMTP_PORT=${smtp_port_input:-587}
    
    # Email remitente
    while true; do
        read -p "Email remitente: " SENDER_EMAIL
        if validate_email "$SENDER_EMAIL"; then
            break
        else
            echo "❌ Email inválido"
        fi
    done
    
    # Contraseña
    echo
    echo "⚠️ Para Gmail: use una 'Contraseña de Aplicación'"
    echo "   Generar en: https://myaccount.google.com/apppasswords"
    read -s -p "Contraseña del remitente: " SENDER_PASSWORD
    echo
    
    # Destinatarios
    echo
    echo "📧 Destinatarios (separados por comas):"
    read -p "Emails destinatarios: " RECIPIENT_EMAILS
    
    log_success "Email configurado"
}

# Crear aplicación principal
create_main_application() {
    log_step "Creando aplicación principal..."
    
    cat > "$INSTALL_DIR/wazuh_ip_reputation.py" << 'APPEOF'
#!/usr/bin/env python3
"""
Wazuh IP Reputation Checker v2.0.0
Analiza IPs de logs de Wazuh y verifica su reputación
"""

import json
import time
import re
import requests
import logging
import smtplib
import mysql.connector
import configparser
import schedule
import sys
import os
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Dict, List, Optional, Tuple
import urllib3

# Deshabilitar advertencias SSL para desarrollo
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class WazuhIPReputationChecker:
    def __init__(self, config_file: str = '/etc/wazuh-ip-reputation/config.ini'):
        """Inicializa el checker con la configuración especificada"""
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        
        # Configuración de logging
        log_level = self.config.get('general', 'log_level', fallback='INFO')
        log_file = self.config.get('general', 'log_file', fallback='/var/log/wazuh-ip-reputation/wazuh-ip-reputation.log')
        
        # Crear directorio de logs si no existe
        os.makedirs(os.path.dirname(log_file), exist_ok=True)
        
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Conexión a base de datos
        self.db_config = {
            'host': self.config.get('database', 'host'),
            'port': self.config.getint('database', 'port'),
            'database': self.config.get('database', 'database'),
            'user': self.config.get('database', 'user'),
            'password': self.config.get('database', 'password')
        }
        
        # Configuración de Wazuh
        self.wazuh_config = {
            'host': self.config.get('wazuh', 'host'),
            'port': self.config.getint('wazuh', 'port'),
            'username': self.config.get('wazuh', 'username'),
            'password': self.config.get('wazuh', 'password'),
            'verify_ssl': self.config.getboolean('wazuh', 'verify_ssl', fallback=False)
        }
        
        # API Keys
        self.virustotal_api_key = self.config.get('apis', 'virustotal_key', fallback='')
        self.abuseipdb_api_key = self.config.get('apis', 'abuseipdb_key', fallback='')
        self.shodan_api_key = self.config.get('apis', 'shodan_key', fallback='')
        
        # Configuración de email
        self.email_enabled = self.config.getboolean('email', 'enabled', fallback=False)
        self.email_config = {
            'smtp_server': self.config.get('email', 'smtp_server', fallback=''),
            'smtp_port': self.config.getint('email', 'smtp_port', fallback=587),
            'sender': self.config.get('email', 'sender_email', fallback=''),
            'password': self.config.get('email', 'sender_password', fallback=''),
            'recipients': self.config.get('email', 'recipient_emails', fallback='').split(',')
        }
        
        # Umbrales de riesgo
        self.risk_thresholds = {
            'critical': self.config.getint('thresholds', 'critical', fallback=90),
            'high': self.config.getint('thresholds', 'high', fallback=70),
            'medium': self.config.getint('thresholds', 'medium', fallback=40),
            'low': self.config.getint('thresholds', 'low', fallback=20)
        }
        
        # Cache
        self.cache_duration = self.config.getint('general', 'cache_duration', fallback=3600)
        self.check_interval = self.config.getint('general', 'check_interval', fallback=300)
        
        self.logger.info("Wazuh IP Reputation Checker v2.0.0 iniciado")
        
    def get_db_connection(self):
        """Obtiene conexión a la base de datos"""
        try:
            return mysql.connector.connect(**self.db_config)
        except Exception as e:
            self.logger.error(f"Error conectando a base de datos: {e}")
            return None
    
    def get_wazuh_token(self):
        """Obtiene token de autenticación de Wazuh"""
        try:
            auth = (self.wazuh_config['username'], self.wazuh_config['password'])
            url = f"https://{self.wazuh_config['host']}:{self.wazuh_config['port']}/security/user/authenticate"
            
            response = requests.post(
                url, 
                auth=auth, 
                verify=self.wazuh_config['verify_ssl']
            )
            
            if response.status_code == 200:
                return response.json()['data']['token']
            else:
                self.logger.error(f"Error autenticando con Wazuh: {response.status_code}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error obteniendo token de Wazuh: {e}")
            return None
    
    def extract_ips_from_wazuh(self) -> List[Dict]:
        """Extrae IPs de las alertas de Wazuh"""
        token = self.get_wazuh_token()
        if not token:
            return []
        
        try:
            headers = {'Authorization': f'Bearer {token}'}
            base_url = f"https://{self.wazuh_config['host']}:{self.wazuh_config['port']}"
            
            # Obtener alertas recientes
            alerts_url = f"{base_url}/alerts"
            params = {
                'limit': 1000,
                'sort': '-timestamp',
                'q': 'rule.level>=7'  # Solo alertas de nivel 7 o superior
            }
            
            response = requests.get(
                alerts_url, 
                headers=headers, 
                params=params,
                verify=self.wazuh_config['verify_ssl']
            )
            
            if response.status_code != 200:
                self.logger.error(f"Error obteniendo alertas: {response.status_code}")
                return []
            
            alerts = response.json().get('data', {}).get('affected_items', [])
            ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
            extracted_ips = []
            
            for alert in alerts:
                # Buscar IPs en diferentes campos
                alert_data = {
                    'alert_id': alert.get('id', ''),
                    'agent_id': alert.get('agent', {}).get('id', ''),
                    'agent_name': alert.get('agent', {}).get('name', ''),
                    'rule_id': alert.get('rule', {}).get('id', ''),
                    'rule_description': alert.get('rule', {}).get('description', ''),
                    'timestamp': alert.get('timestamp', '')
                }
                
                # Buscar IPs en data
                data_str = str(alert.get('data', {}))
                srcip = alert.get('data', {}).get('srcip', '')
                dstip = alert.get('data', {}).get('dstip', '')
                
                ips_found = set()
                
                # Agregar IPs específicas
                if srcip and self._is_valid_public_ip(srcip):
                    ips_found.add(srcip)
                if dstip and self._is_valid_public_ip(dstip):
                    ips_found.add(dstip)
                
                # Buscar otras IPs en el contenido
                for ip in ip_pattern.findall(data_str):
                    if self._is_valid_public_ip(ip):
                        ips_found.add(ip)
                
                # Agregar cada IP encontrada
                for ip in ips_found:
                    ip_data = alert_data.copy()
                    ip_data['ip'] = ip
                    extracted_ips.append(ip_data)
            
            self.logger.info(f"Extraídas {len(extracted_ips)} IPs de Wazuh")
            return extracted_ips
            
        except Exception as e:
            self.logger.error(f"Error extrayendo IPs de Wazuh: {e}")
            return []
    
    def _is_valid_public_ip(self, ip: str) -> bool:
        """Verifica si una IP es válida y pública"""
        try:
            parts = [int(x) for x in ip.split('.')]
            if len(parts) != 4:
                return False
            
            # Verificar rango válido
            if not all(0 <= part <= 255 for part in parts):
                return False
            
            # Excluir IPs privadas
            if (parts[0] == 10 or
                (parts[0] == 172 and 16 <= parts[1] <= 31) or
                (parts[0] == 192 and parts[1] == 168) or
                parts[0] == 127 or
                parts[0] == 0 or
                parts[0] >= 224):
                return False
            
            return True
            
        except (ValueError, AttributeError):
            return False
    
    def is_ip_cached(self, ip: str) -> bool:
        """Verifica si una IP está en cache"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return False
            
            cursor = conn.cursor()
            cache_time = datetime.now() - timedelta(seconds=self.cache_duration)
            
            cursor.execute("""
                SELECT COUNT(*) FROM ip_reputation 
                WHERE ip_address = %s AND last_checked > %s
            """, (ip, cache_time))
            
            count = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            
            return count > 0
            
        except Exception as e:
            self.logger.error(f"Error verificando cache: {e}")
            return False
    
    def check_virustotal(self, ip: str) -> Dict:
        """Verifica reputación en VirusTotal"""
        if not self.virustotal_api_key:
            return {}
        
        try:
            url = f"https://www.virustotal.com/api/v3/ip-addresses/{ip}"
            headers = {'x-apikey': self.virustotal_api_key}
            
            response = requests.get(url, headers=headers, timeout=30)
            
            if response.status_code == 200:
                data = response.json()['data']['attributes']
                
                # Analizar resultados
                last_analysis = data.get('last_analysis_stats', {})
                
                return {
                    'detections': last_analysis.get('malicious', 0),
                    'total_engines': sum(last_analysis.values()),
                    'malicious_votes': data.get('total_votes', {}).get('malicious', 0),
                    'suspicious_votes': data.get('total_votes', {}).get('suspicious', 0)
                }
            elif response.status_code == 429:
                self.logger.warning("Límite de API de VirusTotal alcanzado")
            else:
                self.logger.error(f"Error en VirusTotal: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Error consultando VirusTotal: {e}")
        
        return {}
    
    def check_abuseipdb(self, ip: str) -> Dict:
        """Verifica reputación en AbuseIPDB"""
        if not self.abuseipdb_api_key:
            return {}
        
        try:
            url = "https://api.abuseipdb.com/api/v2/check"
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()['data']
                
                return {
                    'confidence_score': data.get('abuseConfidenceScore', 0),
                    'usage_type': data.get('usageType', ''),
                    'isp': data.get('isp', ''),
                    'country_code': data.get('countryCode', ''),
                    'is_whitelisted': data.get('isWhitelisted', False)
                }
            elif response.status_code == 429:
                self.logger.warning("Límite de API de AbuseIPDB alcanzado")
            else:
                self.logger.error(f"Error en AbuseIPDB: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Error consultando AbuseIPDB: {e}")
        
        return {}
    
    def check_shodan(self, ip: str) -> Dict:
        """Verifica información en Shodan"""
        if not self.shodan_api_key:
            return {}
        
        try:
            import shodan
            api = shodan.Shodan(self.shodan_api_key)
            
            host = api.host(ip)
            
            return {
                'ports': [item['port'] for item in host.get('data', [])],
                'vulns': host.get('vulns', []),
                'tags': host.get('tags', []),
                'os': host.get('os', ''),
                'org': host.get('org', '')
            }
            
        except shodan.APIError as e:
            if e.value != "No information available for that IP.":
                self.logger.error(f"Error en Shodan API: {e}")
        except Exception as e:
            self.logger.error(f"Error consultando Shodan: {e}")
        
        return {}
    
    def calculate_risk_score(self, vt_data: Dict, abuse_data: Dict, shodan_data: Dict) -> Tuple[int, str]:
        """Calcula el score de riesgo basado en los datos recopilados"""
        risk_score = 0
        
        # VirusTotal scoring
        if vt_data:
            if vt_data.get('detections', 0) > 0:
                risk_score += min(vt_data['detections'] * 10, 40)
            if vt_data.get('malicious_votes', 0) > 0:
                risk_score += min(vt_data['malicious_votes'] * 5, 20)
        
        # AbuseIPDB scoring
        if abuse_data:
            confidence = abuse_data.get('confidence_score', 0)
            risk_score += min(confidence, 40)
        
        # Shodan scoring
        if shodan_data:
            if shodan_data.get('vulns'):
                risk_score += min(len(shodan_data['vulns']) * 10, 30)
            if 'honeypot' in shodan_data.get('tags', []):
                risk_score -= 20  # Reducir score si es honeypot
        
        # Determinar nivel de riesgo
        risk_score = max(0, min(100, risk_score))
        
        if risk_score >= self.risk_thresholds['critical']:
            risk_level = 'CRITICAL'
        elif risk_score >= self.risk_thresholds['high']:
            risk_level = 'HIGH'
        elif risk_score >= self.risk_thresholds['medium']:
            risk_level = 'MEDIUM'
        elif risk_score >= self.risk_thresholds['low']:
            risk_level = 'LOW'
        else:
            risk_level = 'SAFE'
        
        return risk_score, risk_level
    
    def analyze_ip_reputation(self, ip: str) -> Dict:
        """Analiza la reputación completa de una IP"""
        self.logger.info(f"Analizando reputación de IP: {ip}")
        
        # Verificar APIs disponibles
        vt_data = self.check_virustotal(ip) if self.virustotal_api_key else {}
        time.sleep(1)  # Rate limiting
        
        abuse_data = self.check_abuseipdb(ip) if self.abuseipdb_api_key else {}
        time.sleep(1)
        
        shodan_data = self.check_shodan(ip) if self.shodan_api_key else {}
        
        # Calcular score de riesgo
        risk_score, risk_level = self.calculate_risk_score(vt_data, abuse_data, shodan_data)
        
        # Determinar si es maliciosa o sospechosa
        is_malicious = risk_level in ['CRITICAL', 'HIGH']
        is_suspicious = risk_level == 'MEDIUM'
        
        result = {
            'ip': ip,
            'risk_score': risk_score,
            'risk_level': risk_level,
            'is_malicious': is_malicious,
            'is_suspicious': is_suspicious,
            'virustotal': vt_data,
            'abuseipdb': abuse_data,
            'shodan': shodan_data,
            'timestamp': datetime.now()
        }
        
        return result
    
    def save_reputation_result(self, result: Dict):
        """Guarda el resultado en la base de datos"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return
            
            cursor = conn.cursor()
            
            # Convertir datos complejos a JSON
            shodan_ports = json.dumps(result['shodan'].get('ports', []))
            shodan_vulns = json.dumps(result['shodan'].get('vulns', []))
            shodan_tags = json.dumps(result['shodan'].get('tags', []))
            
            # Verificar si ya existe
            cursor.execute("SELECT id FROM ip_reputation WHERE ip_address = %s", (result['ip'],))
            existing = cursor.fetchone()
            
            if existing:
                # Actualizar
                cursor.execute("""
                    UPDATE ip_reputation SET
                        vt_detections = %s,
                        vt_total_engines = %s,
                        vt_malicious_votes = %s,
                        vt_suspicious_votes = %s,
                        abuse_confidence_score = %s,
                        abuse_usage_type = %s,
                        abuse_isp = %s,
                        abuse_country_code = %s,
                        abuse_is_whitelisted = %s,
                        shodan_ports = %s,
                        shodan_vulns = %s,
                        shodan_tags = %s,
                        shodan_os = %s,
                        shodan_org = %s,
                        risk_score = %s,
                        risk_level = %s,
                        is_malicious = %s,
                        is_suspicious = %s,
                        last_checked = NOW(),
                        check_count = check_count + 1
                    WHERE ip_address = %s
                """, (
                    result['virustotal'].get('detections', 0),
                    result['virustotal'].get('total_engines', 0),
                    result['virustotal'].get('malicious_votes', 0),
                    result['virustotal'].get('suspicious_votes', 0),
                    result['abuseipdb'].get('confidence_score', 0),
                    result['abuseipdb'].get('usage_type', ''),
                    result['abuseipdb'].get('isp', ''),
                    result['abuseipdb'].get('country_code', ''),
                    result['abuseipdb'].get('is_whitelisted', False),
                    shodan_ports,
                    shodan_vulns,
                    shodan_tags,
                    result['shodan'].get('os', ''),
                    result['shodan'].get('org', ''),
                    result['risk_score'],
                    result['risk_level'],
                    result['is_malicious'],
                    result['is_suspicious'],
                    result['ip']
                ))
            else:
                # Insertar nuevo
                cursor.execute("""
                    INSERT INTO ip_reputation (
                        ip_address, vt_detections, vt_total_engines,
                        vt_malicious_votes, vt_suspicious_votes,
                        abuse_confidence_score, abuse_usage_type, abuse_isp,
                        abuse_country_code, abuse_is_whitelisted,
                        shodan_ports, shodan_vulns, shodan_tags,
                        shodan_os, shodan_org,
                        risk_score, risk_level, is_malicious, is_suspicious
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                """, (
                    result['ip'],
                    result['virustotal'].get('detections', 0),
                    result['virustotal'].get('total_engines', 0),
                    result['virustotal'].get('malicious_votes', 0),
                    result['virustotal'].get('suspicious_votes', 0),
                    result['abuseipdb'].get('confidence_score', 0),
                    result['abuseipdb'].get('usage_type', ''),
                    result['abuseipdb'].get('isp', ''),
                    result['abuseipdb'].get('country_code', ''),
                    result['abuseipdb'].get('is_whitelisted', False),
                    shodan_ports,
                    shodan_vulns,
                    shodan_tags,
                    result['shodan'].get('os', ''),
                    result['shodan'].get('org', ''),
                    result['risk_score'],
                    result['risk_level'],
                    result['is_malicious'],
                    result['is_suspicious']
                ))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            self.logger.info(f"Resultado guardado para IP {result['ip']}")
            
        except Exception as e:
            self.logger.error(f"Error guardando resultado: {e}")
    
    def save_processed_ip(self, ip_data: Dict):
        """Guarda registro de IP procesada de Wazuh"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return
            
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO processed_ips (
                    ip_address, source_alert_id, source_agent_id,
                    source_agent_name, source_rule_id, source_rule_description
                ) VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                ip_data['ip'],
                ip_data.get('alert_id', ''),
                ip_data.get('agent_id', ''),
                ip_data.get('agent_name', ''),
                ip_data.get('rule_id', ''),
                ip_data.get('rule_description', '')
            ))
            
            conn.commit()
            cursor.close()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error guardando IP procesada: {e}")
    
    def update_system_stats(self, total_checked: int, malicious: int, suspicious: int, alerts: int):
        """Actualiza estadísticas del sistema"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return
            
            cursor = conn.cursor()
            today = datetime.now().date()
            
            cursor.execute("""
                INSERT INTO system_stats (
                    stat_date, total_ips_checked, malicious_ips_found,
                    suspicious_ips_found, alerts_sent
                ) VALUES (%s, %s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE
                    total_ips_checked = total_ips_checked + VALUES(total_ips_checked),
                    malicious_ips_found = malicious_ips_found + VALUES(malicious_ips_found),
                    suspicious_ips_found = suspicious_ips_found + VALUES(suspicious_ips_found),
                    alerts_sent = alerts_sent + VALUES(alerts_sent)
            """, (today, total_checked, malicious, suspicious, alerts))
            
            conn.commit()
            cursor.close()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error actualizando estadísticas: {e}")
    
    def send_email_alert(self, ips_data: List[Dict]):
        """Envía alerta por email"""
        if not self.email_enabled or not ips_data:
            return
        
        try:
            # Crear mensaje
            msg = MIMEMultipart('alternative')
            msg['From'] = self.email_config['sender']
            msg['To'] = ', '.join(self.email_config['recipients'])
            msg['Subject'] = f"🚨 Alerta Wazuh: {len(ips_data)} IPs Maliciosas Detectadas"
            
            # Contenido HTML
            html_content = self._create_email_html(ips_data)
            
            # Contenido texto
            text_content = self._create_email_text(ips_data)
            
            msg.attach(MIMEText(text_content, 'plain'))
            msg.attach(MIMEText(html_content, 'html'))
            
            # Enviar
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            server.starttls()
            server.login(self.email_config['sender'], self.email_config['password'])
            server.send_message(msg)
            server.quit()
            
            self.logger.info(f"Alerta enviada a {len(self.email_config['recipients'])} destinatarios")
            
            # Registrar envío
            self._log_email_sent(ips_data)
            
        except Exception as e:
            self.logger.error(f"Error enviando email: {e}")
    
    def _create_email_html(self, ips_data: List[Dict]) -> str:
        """Crea contenido HTML para el email"""
        html = '''
        <html>
        <head>
            <style>
                body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f4f4f4; }
                .container { background-color: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
                .header { background-color: #dc3545; color: white; padding: 20px; text-align: center; border-radius: 8px 8px 0 0; margin: -20px -20px 20px -20px; }
                .ip-card { border: 1px solid #ddd; padding: 15px; margin: 10px 0; border-radius: 5px; }
                .critical { border-left: 5px solid #dc3545; }
                .high { border-left: 5px solid #fd7e14; }
                .medium { border-left: 5px solid #ffc107; }
                .metric { display: inline-block; margin: 5px 15px 5px 0; }
                .label { font-weight: bold; color: #666; }
                .value { color: #333; }
                .footer { text-align: center; color: #666; font-size: 12px; margin-top: 30px; }
            </style>
        </head>
        <body>
            <div class="container">
                <div class="header">
                    <h1>🚨 Alerta de Seguridad Wazuh</h1>
                    <p>IPs Maliciosas Detectadas</p>
                </div>
        '''
        
        # Agrupar por nivel de riesgo
        critical = [ip for ip in ips_data if ip['risk_level'] == 'CRITICAL']
        high = [ip for ip in ips_data if ip['risk_level'] == 'HIGH']
        medium = [ip for ip in ips_data if ip['risk_level'] == 'MEDIUM']
        
        if critical:
            html += f'<h2 style="color: #dc3545;">⚠️ CRÍTICAS ({len(critical)})</h2>'
            for ip_info in critical[:5]:
                html += self._format_ip_html(ip_info, 'critical')
        
        if high:
            html += f'<h2 style="color: #fd7e14;">⚠️ ALTAS ({len(high)})</h2>'
            for ip_info in high[:5]:
                html += self._format_ip_html(ip_info, 'high')
        
        if medium:
            html += f'<h2 style="color: #ffc107;">⚠️ MEDIAS ({len(medium)})</h2>'
            for ip_info in medium[:3]:
                html += self._format_ip_html(ip_info, 'medium')
        
        html += '''
                <div class="footer">
                    <p>Este es un mensaje automático del sistema Wazuh IP Reputation Checker</p>
                    <p>Para más detalles, consulte el panel de Wazuh o ejecute: wazuh-reputation status</p>
                </div>
            </div>
        </body>
        </html>
        '''
        
        return html
    
    def _format_ip_html(self, ip_info: Dict, severity_class: str) -> str:
        """Formatea información de una IP para HTML"""
        html = f'<div class="ip-card {severity_class}">'
        html += f'<h3>{ip_info["ip"]}</h3>'
        html += f'<div class="metric"><span class="label">Score de Riesgo:</span> <span class="value">{ip_info["risk_score"]}/100</span></div>'
        html += f'<div class="metric"><span class="label">Nivel:</span> <span class="value">{ip_info["risk_level"]}</span></div>'
        
        if ip_info.get('abuseipdb', {}).get('country_code'):
            html += f'<div class="metric"><span class="label">País:</span> <span class="value">{ip_info["abuseipdb"]["country_code"]}</span></div>'
        
        if ip_info.get('abuseipdb', {}).get('isp'):
            html += f'<div class="metric"><span class="label">ISP:</span> <span class="value">{ip_info["abuseipdb"]["isp"]}</span></div>'
        
        if ip_info.get('virustotal', {}).get('detections'):
            html += f'<div class="metric"><span class="label">VT Detecciones:</span> <span class="value">{ip_info["virustotal"]["detections"]}/{ip_info["virustotal"]["total_engines"]}</span></div>'
        
        if ip_info.get('shodan', {}).get('ports'):
            ports = ', '.join(map(str, ip_info['shodan']['ports'][:5]))
            html += f'<div class="metric"><span class="label">Puertos:</span> <span class="value">{ports}</span></div>'
        
        html += '</div>'
        return html
    
    def _create_email_text(self, ips_data: List[Dict]) -> str:
        """Crea contenido de texto plano para el email"""
        text = "ALERTA DE SEGURIDAD WAZUH\n"
        text += "=" * 50 + "\n\n"
        text += f"Se han detectado {len(ips_data)} IPs con actividad maliciosa\n"
        text += f"Fecha: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        for ip_info in ips_data[:10]:
            text += f"\nIP: {ip_info['ip']}\n"
            text += f"  Nivel de Riesgo: {ip_info['risk_level']} ({ip_info['risk_score']}/100)\n"
            
            if ip_info.get('abuseipdb'):
                text += f"  País: {ip_info['abuseipdb'].get('country_code', 'N/A')}\n"
                text += f"  ISP: {ip_info['abuseipdb'].get('isp', 'N/A')}\n"
            
            text += "-" * 30 + "\n"
        
        if len(ips_data) > 10:
            text += f"\n... y {len(ips_data) - 10} IPs más\n"
        
        return text
    
    def _log_email_sent(self, ips_data: List[Dict]):
        """Registra el envío de email en la base de datos"""
        try:
            conn = self.get_db_connection()
            if not conn:
                return
            
            cursor = conn.cursor()
            
            for ip_info in ips_data:
                cursor.execute("""
                    INSERT INTO sent_alerts (
                        ip_address, alert_type, alert_level,
                        recipients, subject
                    ) VALUES (%s, %s, %s, %s, %s)
                """, (
                    ip_info['ip'],
                    'EMAIL',
                    ip_info['risk_level'],
                    ', '.join(self.email_config['recipients']),
                    f"Alerta: IP {ip_info['ip']} - {ip_info['risk_level']}"
                ))
            
            conn.commit()
            cursor.close()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error registrando alertas enviadas: {e}")
    
    def should_send_alert(self, ip: str, risk_level: str) -> bool:
        """Determina si se debe enviar una alerta para esta IP"""
        if risk_level not in ['CRITICAL', 'HIGH', 'MEDIUM']:
            return False
        
        try:
            conn = self.get_db_connection()
            if not conn:
                return True
            
            cursor = conn.cursor()
            
            # Verificar última alerta enviada
            hours_threshold = 24  # No repetir alertas en 24 horas
            cursor.execute("""
                SELECT COUNT(*) FROM sent_alerts
                WHERE ip_address = %s 
                AND sent_at > DATE_SUB(NOW(), INTERVAL %s HOUR)
            """, (ip, hours_threshold))
            
            count = cursor.fetchone()[0]
            cursor.close()
            conn.close()
            
            return count == 0
            
        except Exception as e:
            self.logger.error(f"Error verificando alertas previas: {e}")
            return True
    
    def run_analysis(self):
        """Ejecuta el análisis completo"""
        self.logger.info("=" * 60)
        self.logger.info("Iniciando análisis de reputación de IPs")
        self.logger.info("=" * 60)
        
        # Extraer IPs de Wazuh
        wazuh_ips = self.extract_ips_from_wazuh()
        
        if not wazuh_ips:
            self.logger.info("No se encontraron IPs nuevas para analizar")
            return
        
        # Estadísticas
        processed_count = 0
        malicious_count = 0
        suspicious_count = 0
        alerts_to_send = []
        
        # Procesar cada IP
        unique_ips = {}
        for ip_data in wazuh_ips:
            ip = ip_data['ip']
            if ip not in unique_ips:
                unique_ips[ip] = ip_data
        
        self.logger.info(f"Procesando {len(unique_ips)} IPs únicas")
        
        for ip, ip_data in unique_ips.items():
            try:
                # Verificar cache
                if self.is_ip_cached(ip):
                    self.logger.debug(f"IP {ip} en cache, omitiendo")
                    continue
                
                # Analizar reputación
                result = self.analyze_ip_reputation(ip)
                
                # Guardar resultado
                self.save_reputation_result(result)
                
                # Guardar registro de procesamiento
                self.save_processed_ip(ip_data)
                
                # Verificar si enviar alerta
                if self.should_send_alert(ip, result['risk_level']):
                    alerts_to_send.append(result)
                
                # Actualizar estadísticas
                processed_count += 1
                if result['is_malicious']:
                    malicious_count += 1
                elif result['is_suspicious']:
                    suspicious_count += 1
                
                self.logger.info(
                    f"IP {ip}: Score={result['risk_score']}, "
                    f"Nivel={result['risk_level']}, "
                    f"VT={result['virustotal'].get('detections', 'N/A')}, "
                    f"Abuse={result['abuseipdb'].get('confidence_score', 'N/A')}%"
                )
                
            except Exception as e:
                self.logger.error(f"Error procesando IP {ip}: {e}")
        
        # Enviar alertas si hay
        if alerts_to_send and self.email_enabled:
            self.send_email_alert(alerts_to_send)
        
        # Actualizar estadísticas
        self.update_system_stats(
            processed_count, 
            malicious_count, 
            suspicious_count,
            len(alerts_to_send)
        )
        
        # Resumen
        self.logger.info("=" * 60)
        self.logger.info("RESUMEN DEL ANÁLISIS")
        self.logger.info(f"IPs procesadas: {processed_count}")
        self.logger.info(f"IPs maliciosas: {malicious_count}")
        self.logger.info(f"IPs sospechosas: {suspicious_count}")
        self.logger.info(f"Alertas enviadas: {len(alerts_to_send)}")
        self.logger.info("=" * 60)
    
    def run_continuous(self):
        """Ejecuta el análisis de forma continua"""
        self.logger.info(f"Iniciando monitoreo continuo cada {self.check_interval} segundos")
        
        while True:
            try:
                self.run_analysis()
                self.logger.info(f"Esperando {self.check_interval} segundos para próximo análisis")
                time.sleep(self.check_interval)
                
            except KeyboardInterrupt:
                self.logger.info("Deteniendo monitoreo por interrupción de usuario")
                break
            except Exception as e:
                self.logger.error(f"Error en monitoreo continuo: {e}")
                time.sleep(60)  # Esperar antes de reintentar

def main():
    """Función principal"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Wazuh IP Reputation Checker v2.0.0')
    parser.add_argument('--config', default='/etc/wazuh-ip-reputation/config.ini',
                       help='Archivo de configuración')
    parser.add_argument('--once', action='store_true',
                       help='Ejecutar análisis una sola vez')
    parser.add_argument('--continuous', action='store_true',
                       help='Ejecutar análisis continuo')
    parser.add_argument('--test-apis', action='store_true',
                       help='Probar conexión con APIs')
    
    args = parser.parse_args()
    
    # Verificar archivo de configuración
    if not os.path.exists(args.config):
        print(f"Error: Archivo de configuración no encontrado: {args.config}")
        sys.exit(1)
    
    # Crear instancia
    checker = WazuhIPReputationChecker(args.config)
    
    if args.test_apis:
        print("Probando APIs configuradas...")
        
        # Probar Wazuh
        if checker.get_wazuh_token():
            print("✅ Wazuh API: OK")
        else:
            print("❌ Wazuh API: Error")
        
        # Probar otras APIs con una IP de ejemplo
        test_ip = "8.8.8.8"
        
        if checker.virustotal_api_key:
            vt_result = checker.check_virustotal(test_ip)
            if vt_result:
                print("✅ VirusTotal API: OK")
            else:
                print("❌ VirusTotal API: Error")
        
        if checker.abuseipdb_api_key:
            abuse_result = checker.check_abuseipdb(test_ip)
            if abuse_result:
                print("✅ AbuseIPDB API: OK")
            else:
                print("❌ AbuseIPDB API: Error")
        
        if checker.shodan_api_key:
            shodan_result = checker.check_shodan(test_ip)
            print("✅ Shodan API: OK" if shodan_result is not None else "❌ Shodan API: Error")
        
    elif args.once:
        checker.run_analysis()
    elif args.continuous:
        checker.run_continuous()
    else:
        print("Uso: wazuh_ip_reputation.py --once | --continuous")
        print("Use --help para más información")
        sys.exit(1)

if __name__ == "__main__":
    main()
APPEOF
    
    chmod +x "$INSTALL_DIR/wazuh_ip_reputation.py"
    chown "$INSTALL_USER:$INSTALL_GROUP" "$INSTALL_DIR/wazuh_ip_reputation.py"
    log_success "Aplicación principal creada"
}

# Crear archivo de configuración
create_config_file() {
    log_step "Creando archivo de configuración..."
    
    cat > "$CONFIG_DIR/config.ini" << CONFEOF
[general]
log_level = INFO
log_file = /var/log/wazuh-ip-reputation/wazuh-ip-reputation.log
check_interval = ${CHECK_INTERVAL}
cache_duration = 3600

[database]
host = ${DB_HOST}
port = ${DB_PORT}
database = ${DB_NAME}
user = ${DB_USER}
password = ${DB_PASSWORD}

[wazuh]
host = ${WAZUH_HOST}
port = ${WAZUH_PORT}
username = ${WAZUH_USERNAME}
password = ${WAZUH_PASSWORD}
verify_ssl = false

[apis]
virustotal_key = ${VIRUSTOTAL_API_KEY}
abuseipdb_key = ${ABUSEIPDB_API_KEY}
shodan_key = ${SHODAN_API_KEY}

[email]
enabled = $([ -n "$SENDER_EMAIL" ] && echo "true" || echo "false")
smtp_server = ${SMTP_SERVER}
smtp_port = ${SMTP_PORT}
sender_email = ${SENDER_EMAIL}
sender_password = ${SENDER_PASSWORD}
recipient_emails = ${RECIPIENT_EMAILS}

[thresholds]
critical = 90
high = 70
medium = 40
low = 20
CONFEOF
    
    # Configurar permisos
    chown root:"$INSTALL_GROUP" "$CONFIG_DIR/config.ini"
    chmod 640 "$CONFIG_DIR/config.ini"
    
    log_success "Archivo de configuración creado"
}

# Crear herramientas de administración
create_admin_tools() {
    log_step "Creando herramientas de administración..."
    
    # Script principal de administración
    cat > "$BIN_DIR/wazuh-reputation" << 'ADMINEOF'
#!/bin/bash

INSTALL_DIR="/opt/wazuh-ip-reputation"
CONFIG_FILE="/etc/wazuh-ip-reputation/config.ini"
SERVICE_NAME="wazuh-ip-reputation"

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

show_help() {
    echo "Wazuh IP Reputation Checker - Herramienta de Administración"
    echo
    echo "Uso: wazuh-reputation [comando] [opciones]"
    echo
    echo "Comandos:"
    echo "  start              Iniciar el servicio"
    echo "  stop               Detener el servicio"
    echo "  restart            Reiniciar el servicio"
    echo "  status             Mostrar estado del servicio"
    echo "  check-once         Ejecutar análisis una vez"
    echo "  test-apis          Probar conexión con APIs"
    echo "  show-stats         Mostrar estadísticas"
    echo "  show-ips [N]       Mostrar últimas N IPs analizadas (default: 10)"
    echo "  show-alerts [N]    Mostrar últimas N alertas enviadas (default: 10)"
    echo "  clear-cache        Limpiar cache de IPs"
    echo "  logs               Ver logs en tiempo real"
    echo "  config             Editar configuración"
    echo "  backup             Crear backup de la base de datos"
    echo "  help               Mostrar esta ayuda"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        echo -e "${RED}Error: Este comando requiere permisos de root${NC}"
        exit 1
    fi
}

case "$1" in
    start)
        check_root
        systemctl start $SERVICE_NAME
        echo -e "${GREEN}Servicio iniciado${NC}"
        ;;
    
    stop)
        check_root
        systemctl stop $SERVICE_NAME
        echo -e "${YELLOW}Servicio detenido${NC}"
        ;;
    
    restart)
        check_root
        systemctl restart $SERVICE_NAME
        echo -e "${GREEN}Servicio reiniciado${NC}"
        ;;
    
    status)
        echo -e "${BLUE}Estado del servicio:${NC}"
        systemctl status $SERVICE_NAME --no-pager
        
        echo
        echo -e "${BLUE}Estadísticas rápidas:${NC}"
        sudo -u wazuh-reputation $INSTALL_DIR/venv/bin/python << EOF
import mysql.connector
import configparser

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    conn = mysql.connector.connect(
        host=config.get('database', 'host'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    cursor = conn.cursor()
    
    # Total IPs
    cursor.execute("SELECT COUNT(*) FROM ip_reputation")
    total_ips = cursor.fetchone()[0]
    
    # IPs por nivel
    cursor.execute("""
        SELECT risk_level, COUNT(*) 
        FROM ip_reputation 
        GROUP BY risk_level
    """)
    levels = dict(cursor.fetchall())
    
    print(f"Total IPs analizadas: {total_ips}")
    print(f"Críticas: {levels.get('CRITICAL', 0)}")
    print(f"Altas: {levels.get('HIGH', 0)}")
    print(f"Medias: {levels.get('MEDIUM', 0)}")
    print(f"Bajas: {levels.get('LOW', 0)}")
    print(f"Seguras: {levels.get('SAFE', 0)}")
    
    cursor.close()
    conn.close()
except Exception as e:
    print(f"Error obteniendo estadísticas: {e}")
EOF
        ;;
    
    check-once)
        check_root
        echo -e "${BLUE}Ejecutando análisis único...${NC}"
        sudo -u wazuh-reputation $INSTALL_DIR/venv/bin/python $INSTALL_DIR/wazuh_ip_reputation.py --once
        ;;
    
    test-apis)
        check_root
        echo -e "${BLUE}Probando APIs...${NC}"
        sudo -u wazuh-reputation $INSTALL_DIR/venv/bin/python $INSTALL_DIR/wazuh_ip_reputation.py --test-apis
        ;;
    
    show-stats)
        echo -e "${BLUE}Estadísticas del sistema:${NC}"
        sudo -u wazuh-reputation $INSTALL_DIR/venv/bin/python << EOF
import mysql.connector
import configparser
from datetime import datetime, timedelta
from tabulate import tabulate

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    conn = mysql.connector.connect(
        host=config.get('database', 'host'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    cursor = conn.cursor()
    
    # Estadísticas de los últimos 7 días
    cursor.execute("""
        SELECT 
            stat_date,
            total_ips_checked,
            malicious_ips_found,
            suspicious_ips_found,
            alerts_sent
        FROM system_stats
        WHERE stat_date >= DATE_SUB(CURDATE(), INTERVAL 7 DAY)
        ORDER BY stat_date DESC
    """)
    
    stats = cursor.fetchall()
    
    if stats:
        headers = ['Fecha', 'IPs Analizadas', 'Maliciosas', 'Sospechosas', 'Alertas']
        print(tabulate(stats, headers=headers, tablefmt='grid'))
    else:
        print("No hay estadísticas disponibles")
    
    cursor.close()
    conn.close()
except Exception as e:
    print(f"Error: {e}")
EOF
        ;;
    
    show-ips)
        limit="${2:-10}"
        echo -e "${BLUE}Últimas $limit IPs analizadas:${NC}"
        sudo -u wazuh-reputation $INSTALL_DIR/venv/bin/python << EOF
import mysql.connector
import configparser
from tabulate import tabulate

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    conn = mysql.connector.connect(
        host=config.get('database', 'host'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            ip_address,
            risk_level,
            risk_score,
            abuse_country_code,
            DATE_FORMAT(last_checked, '%Y-%m-%d %H:%i') as last_checked
        FROM ip_reputation
        ORDER BY last_checked DESC
        LIMIT %s
    """, ($limit,))
    
    ips = cursor.fetchall()
    
    if ips:
        headers = ['IP', 'Nivel', 'Score', 'País', 'Última Verificación']
        print(tabulate(ips, headers=headers, tablefmt='grid'))
    else:
        print("No hay IPs registradas")
    
    cursor.close()
    conn.close()
except Exception as e:
    print(f"Error: {e}")
EOF
        ;;
    
    show-alerts)
        limit="${2:-10}"
        echo -e "${BLUE}Últimas $limit alertas enviadas:${NC}"
        sudo -u wazuh-reputation $INSTALL_DIR/venv/bin/python << EOF
import mysql.connector
import configparser
from tabulate import tabulate

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    conn = mysql.connector.connect(
        host=config.get('database', 'host'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            ip_address,
            alert_level,
            alert_type,
            DATE_FORMAT(sent_at, '%Y-%m-%d %H:%i') as sent_at
        FROM sent_alerts
        ORDER BY sent_at DESC
        LIMIT %s
    """, ($limit,))
    
    alerts = cursor.fetchall()
    
    if alerts:
        headers = ['IP', 'Nivel', 'Tipo', 'Fecha Envío']
        print(tabulate(alerts, headers=headers, tablefmt='grid'))
    else:
        print("No hay alertas registradas")
    
    cursor.close()
    conn.close()
except Exception as e:
    print(f"Error: {e}")
EOF
        ;;
    
    clear-cache)
        check_root
        echo -e "${YELLOW}Limpiando cache de IPs...${NC}"
        # Actualizar last_checked a una fecha antigua para forzar re-análisis
        sudo -u wazuh-reputation $INSTALL_DIR/venv/bin/python << EOF
import mysql.connector
import configparser
from datetime import datetime, timedelta

config = configparser.ConfigParser()
config.read('$CONFIG_FILE')

try:
    conn = mysql.connector.connect(
        host=config.get('database', 'host'),
        database=config.get('database', 'database'),
        user=config.get('database', 'user'),
        password=config.get('database', 'password')
    )
    cursor = conn.cursor()
    
    old_date = datetime.now() - timedelta(days=30)
    cursor.execute("""
        UPDATE ip_reputation 
        SET last_checked = %s
    """, (old_date,))
    
    affected = cursor.rowcount
    conn.commit()
    
    print(f"Cache limpiado. {affected} IPs marcadas para re-análisis")
    
    cursor.close()
    conn.close()
except Exception as e:
    print(f"Error: {e}")
EOF
        ;;
    
    logs)
        echo -e "${BLUE}Mostrando logs en tiempo real (Ctrl+C para salir)...${NC}"
        tail -f /var/log/wazuh-ip-reputation/wazuh-ip-reputation.log
        ;;
    
    config)
        check_root
        ${EDITOR:-nano} $CONFIG_FILE
        echo -e "${YELLOW}Recuerde reiniciar el servicio para aplicar cambios${NC}"
        ;;
    
    backup)
        check_root
        echo -e "${BLUE}Creando backup...${NC}"
        BACKUP_DIR="/var/lib/wazuh-ip-reputation/backups"
        mkdir -p $BACKUP_DIR
        TIMESTAMP=$(date +%Y%m%d_%H%M%S)
        
        # Leer configuración de base de datos
        DB_NAME=$(grep "^database" $CONFIG_FILE | cut -d'=' -f2 | xargs)
        DB_USER=$(grep "^user" $CONFIG_FILE | cut -d'=' -f2 | xargs)
        DB_PASS=$(grep "^password" $CONFIG_FILE | cut -d'=' -f2 | xargs)
        
        mysqldump -u$DB_USER -p$DB_PASS $DB_NAME > "$BACKUP_DIR/backup_${TIMESTAMP}.sql"
        
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}Backup creado: $BACKUP_DIR/backup_${TIMESTAMP}.sql${NC}"
            
            # Mantener solo los últimos 7 backups
            cd $BACKUP_DIR
            ls -t backup_*.sql | tail -n +8 | xargs -r rm
        else
            echo -e "${RED}Error creando backup${NC}"
        fi
        ;;
    
    help|"")
        show_help
        ;;
    
    *)
        echo -e "${RED}Comando no reconocido: $1${NC}"
        echo
        show_help
        exit 1
        ;;
esac
ADMINEOF
    
    chmod +x "$BIN_DIR/wazuh-reputation"
    log_success "Herramientas de administración creadas"
}

# Crear servicio systemd
create_systemd_service() {
    log_step "Creando servicio systemd..."
    
    cat > "/etc/systemd/system/$SERVICE_NAME.service" << SERVICEEOF
[Unit]
Description=Wazuh IP Reputation Checker
Documentation=https://github.com/wazuh/wazuh-ip-reputation
After=network.target mariadb.service mysql.service
Wants=network.target

[Service]
Type=simple
User=$INSTALL_USER
Group=$INSTALL_GROUP
WorkingDirectory=$INSTALL_DIR

# Comando principal
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/wazuh_ip_reputation.py --continuous

# Reinicio automático
Restart=always
RestartSec=30
StartLimitInterval=200
StartLimitBurst=5

# Configuración de seguridad
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=$LOG_DIR $DATA_DIR
PrivateTmp=yes

# Variables de entorno
Environment="PYTHONUNBUFFERED=1"
Environment="PATH=$INSTALL_DIR/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

# Logs
StandardOutput=journal
StandardError=journal
SyslogIdentifier=$SERVICE_NAME

[Install]
WantedBy=multi-user.target
SERVICEEOF
    
    systemctl daemon-reload
    log_success "Servicio systemd creado"
}

# Configurar logrotate
configure_logrotate() {
    log_step "Configurando rotación de logs..."
    
    cat > "/etc/logrotate.d/$SERVICE_NAME" << LOGROTATEEOF
$LOG_DIR/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 644 $INSTALL_USER $INSTALL_GROUP
    sharedscripts
    postrotate
        systemctl reload $SERVICE_NAME > /dev/null 2>&1 || true
    endscript
}
LOGROTATEEOF
    
    log_success "Logrotate configurado"
}

# Crear scripts adicionales
create_additional_scripts() {
    log_step "Creando scripts adicionales..."
    
    # Script de backup automático
    cat > "$DATA_DIR/scripts/backup.sh" << 'BACKUPEOF'
#!/bin/bash

BACKUP_DIR="/var/lib/wazuh-ip-reputation/backups"
CONFIG_FILE="/etc/wazuh-ip-reputation/config.ini"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOG_FILE="/var/log/wazuh-ip-reputation/backup.log"

# Crear directorio si no existe
mkdir -p "$BACKUP_DIR"

# Función de logging
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" >> "$LOG_FILE"
}

log "Iniciando backup..."

# Leer configuración
DB_NAME=$(grep "^database" $CONFIG_FILE | cut -d'=' -f2 | xargs)
DB_USER=$(grep "^user" $CONFIG_FILE | cut -d'=' -f2 | xargs)
DB_PASS=$(grep "^password" $CONFIG_FILE | cut -d'=' -f2 | xargs)

# Crear backup
if mysqldump -u"$DB_USER" -p"$DB_PASS" "$DB_NAME" > "$BACKUP_DIR/backup_${TIMESTAMP}.sql"; then
    gzip "$BACKUP_DIR/backup_${TIMESTAMP}.sql"
    log "Backup creado: backup_${TIMESTAMP}.sql.gz"
    
    # Eliminar backups antiguos (mantener últimos 7)
    find "$BACKUP_DIR" -name "backup_*.sql.gz" -type f -mtime +7 -delete
    log "Backups antiguos eliminados"
else
    log "ERROR: Fallo al crear backup"
    exit 1
fi

log "Backup completado"
BACKUPEOF
    
    chmod +x "$DATA_DIR/scripts/backup.sh"
    chown "$INSTALL_USER:$INSTALL_GROUP" "$DATA_DIR/scripts/backup.sh"
    
    # Agregar a crontab
    echo "0 2 * * * $INSTALL_USER $DATA_DIR/scripts/backup.sh" > /etc/cron.d/wazuh-ip-reputation-backup
    
    log_success "Scripts adicionales creados"
}

# Finalizar instalación
finalize_installation() {
    log_step "Finalizando instalación..."
    
    # Habilitar servicio
    systemctl enable $SERVICE_NAME
    
    # Iniciar servicio
    if systemctl start $SERVICE_NAME; then
        log_success "Servicio iniciado correctamente"
    else
        log_warn "El servicio no pudo iniciarse automáticamente"
        log_warn "Verifique la configuración y los logs"
    fi
    
    # Verificar permisos finales
    chown -R "$INSTALL_USER:$INSTALL_GROUP" "$INSTALL_DIR"
    chown -R "$INSTALL_USER:$INSTALL_GROUP" "$LOG_DIR"
    chown -R "$INSTALL_USER:$INSTALL_GROUP" "$DATA_DIR"
    
    log_success "Instalación finalizada"
}

# Mostrar resumen
show_summary() {
    log_header "INSTALACIÓN COMPLETADA"
    
    echo -e "${GREEN}✅ Wazuh IP Reputation Checker v${SCRIPT_VERSION} instalado exitosamente${NC}"
    echo
    
    echo "📁 UBICACIONES:"
    echo "   • Aplicación: $INSTALL_DIR"
    echo "   • Configuración: $CONFIG_DIR/config.ini"
    echo "   • Logs: $LOG_DIR/"
    echo "   • Datos: $DATA_DIR/"
    echo "   • Comando: wazuh-reputation"
    echo
    
    echo "📊 CONFIGURACIÓN:"
    echo "   • Base de datos: $DB_TYPE en $DB_HOST:$DB_PORT"
    echo "   • Wazuh: $WAZUH_HOST:$WAZUH_PORT"
    
    if [[ -n "$VIRUSTOTAL_API_KEY" ]]; then
        echo "   • VirusTotal: ✅ Configurado"
    else
        echo "   • VirusTotal: ❌ No configurado"
    fi
    
    if [[ -n "$ABUSEIPDB_API_KEY" ]]; then
        echo "   • AbuseIPDB: ✅ Configurado"
    else
        echo "   • AbuseIPDB: ❌ No configurado"
    fi
    
    if [[ -n "$SHODAN_API_KEY" ]]; then
        echo "   • Shodan: ✅ Configurado"
    else
        echo "   • Shodan: ❌ No configurado"
    fi
    
    if [[ -n "$SENDER_EMAIL" ]]; then
        echo "   • Email: ✅ Configurado"
    else
        echo "   • Email: ❌ No configurado"
    fi
    echo
    
    echo "🚀 PRÓXIMOS PASOS:"
    echo
    echo "1. Verificar el estado del servicio:"
    echo "   sudo wazuh-reputation status"
    echo
    echo "2. Probar las APIs configuradas:"
    echo "   sudo wazuh-reputation test-apis"
    echo
    echo "3. Ejecutar un análisis manual:"
    echo "   sudo wazuh-reputation check-once"
    echo
    echo "4. Ver logs en tiempo real:"
    echo "   sudo wazuh-reputation logs"
    echo
    echo "5. Modificar configuración si es necesario:"
    echo "   sudo wazuh-reputation config"
    echo
    
    if [[ -n "$CURRENT_USER" ]] && [[ "$CURRENT_USER" != "root" ]]; then
        echo -e "${YELLOW}⚠️  NOTA: Se agregó el usuario $CURRENT_USER al grupo $INSTALL_GROUP${NC}"
        echo -e "${YELLOW}   Cierre sesión y vuelva a entrar para aplicar los cambios${NC}"
        echo
    fi
    
    echo "📚 COMANDOS DISPONIBLES:"
    echo "   wazuh-reputation help    - Ver todos los comandos disponibles"
    echo
    
    echo -e "${GREEN}¡Sistema listo para proteger su infraestructura!${NC}"
}

# Función principal
main() {
    show_welcome_banner
    check_prerequisites
    install_dependencies
    create_system_user
    create_directories
    setup_python_environment
    setup_database
    configure_wazuh
    configure_reputation_apis
    configure_email
    create_main_application
    create_config_file
    create_admin_tools
    create_systemd_service
    configure_logrotate
    create_additional_scripts
    finalize_installation
    show_summary
}

# Ejecutar instalación
main "$@"