#!/usr/bin/env python3
"""
Wazuh IP Reputation Checker
Analiza IPs de logs de Wazuh y verifica su reputación usando VirusTotal y AbuseIPDB
"""

import json
import sqlite3
import smtplib
import time
import re
import requests
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import configparser
import sys
import os
from typing import Dict, List, Optional, Tuple

class WazuhIPReputationChecker:
    def __init__(self, config_file: str = "/opt/wazuh-ip-reputation/config"):
        """Inicializa el checker con la configuración especificada"""
        self.config = configparser.ConfigParser()
        self.config.read(config_file)
        
        # Configuración de logging
        log_level = self.config.get('general', 'log_level', fallback='INFO')
        logging.basicConfig(
            level=getattr(logging, log_level),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('/var/log/wazuh-ip-reputation.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)
        
        # Configuración de la base de datos
        self.db_path = self.config.get('database', 'path', fallback='/opt/wazuh-ip-reputation/ip_reputation.db')
        self.init_database()
        
        # URLs de APIs
        self.virustotal_url = "https://www.virustotal.com/vtapi/v2/ip-address/report"
        self.abuseipdb_url = "https://api.abuseipdb.com/api/v2/check"
        
        # Configuración de Wazuh
        self.wazuh_config = {
            'host': self.config.get('wazuh', 'host', fallback='localhost'),
            'port': self.config.getint('wazuh', 'port', fallback=55000),
            'username': self.config.get('wazuh', 'username', fallback='wazuh'),
            'password': self.config.get('wazuh', 'password', fallback='wazuh'),
            'verify_ssl': self.config.getboolean('wazuh', 'verify_ssl', fallback=False)
        }
        
        # Configuración de email
        self.email_config = {
            'smtp_server': self.config.get('email', 'smtp_server', fallback='localhost'),
            'smtp_port': self.config.getint('email', 'smtp_port', fallback=587),
            'username': self.config.get('email', 'username', fallback=''),
            'password': self.config.get('email', 'password', fallback=''),
            'from_email': self.config.get('email', 'from_email', fallback='wazuh@localhost'),
            'to_emails': self.config.get('email', 'to_emails', fallback='admin@localhost').split(','),
            'enabled': self.config.getboolean('email', 'enabled', fallback=False)
        }
        
        # Configuración de APIs
        self.virustotal_api_key = self.config.get('apis', 'virustotal_key', fallback='')
        self.abuseipdb_api_key = self.config.get('apis', 'abuseipdb_key', fallback='')
        
        # Configuración de umbrales
        self.malicious_threshold = self.config.getint('thresholds', 'malicious_threshold', fallback=5)
        self.suspicious_threshold = self.config.getint('thresholds', 'suspicious_threshold', fallback=2)
        self.abuse_confidence_threshold = self.config.getint('thresholds', 'abuse_confidence_threshold', fallback=75)
        
        # Configuración de intervalos
        self.check_interval = self.config.getint('general', 'check_interval', fallback=300)
        self.cache_duration = self.config.getint('general', 'cache_duration', fallback=3600)
        
    def init_database(self):
        """Inicializa la base de datos SQLite"""
        try:
            # Crear directorio si no existe
            os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Tabla para almacenar resultados de reputación
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    virustotal_detections INTEGER DEFAULT 0,
                    virustotal_total INTEGER DEFAULT 0,
                    abuseipdb_confidence INTEGER DEFAULT 0,
                    abuseipdb_usage_type TEXT DEFAULT '',
                    country_code TEXT DEFAULT '',
                    is_malicious BOOLEAN DEFAULT FALSE,
                    is_suspicious BOOLEAN DEFAULT FALSE,
                    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP,
                    alert_sent BOOLEAN DEFAULT FALSE
                )
            ''')
            
            # Tabla para almacenar alertas enviadas
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS sent_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    alert_content TEXT,
                    sent_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Tabla para logs de IPs procesadas
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS processed_ips (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip_address TEXT NOT NULL,
                    source_log TEXT,
                    processed_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Crear índices para mejor rendimiento
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_ip_address ON ip_reputation(ip_address)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_last_updated ON ip_reputation(last_updated)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_processed_at ON processed_ips(processed_at)')
            
            conn.commit()
            conn.close()
            
            self.logger.info("Base de datos inicializada correctamente")
            
        except Exception as e:
            self.logger.error(f"Error inicializando base de datos: {e}")
            sys.exit(1)
    
    def extract_ips_from_logs(self) -> List[str]:
        """Extrae IPs de los logs de Wazuh usando la API"""
        ips = []
        
        try:
            # Obtener alertas recientes de Wazuh
            auth = (self.wazuh_config['username'], self.wazuh_config['password'])
            base_url = f"https://{self.wazuh_config['host']}:{self.wazuh_config['port']}"
            
            # Obtener token de autenticación
            login_url = f"{base_url}/security/user/authenticate"
            login_response = requests.post(login_url, auth=auth, verify=self.wazuh_config['verify_ssl'])
            
            if login_response.status_code == 200:
                token = login_response.json()['data']['token']
                headers = {'Authorization': f'Bearer {token}'}
                
                # Obtener alertas de las últimas horas
                alerts_url = f"{base_url}/alerts"
                params = {
                    'limit': 1000,
                    'sort': '-timestamp'
                }
                
                alerts_response = requests.get(alerts_url, headers=headers, params=params, 
                                             verify=self.wazuh_config['verify_ssl'])
                
                if alerts_response.status_code == 200:
                    alerts = alerts_response.json()['data']['affected_items']
                    
                    # Extraer IPs de las alertas
                    ip_pattern = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')
                    
                    for alert in alerts:
                        # Buscar IPs en diferentes campos
                        fields_to_check = ['data', 'full_log', 'srcip', 'dstip']
                        
                        for field in fields_to_check:
                            if field in alert:
                                field_value = str(alert[field])
                                found_ips = ip_pattern.findall(field_value)
                                
                                for ip in found_ips:
                                    if self.is_valid_ip(ip) and not self.is_private_ip(ip):
                                        ips.append(ip)
                                        
                                        # Registrar IP procesada
                                        self.log_processed_ip(ip, field_value[:200])
                
                self.logger.info(f"Extraídas {len(set(ips))} IPs únicas de Wazuh")
                
            else:
                self.logger.error(f"Error autenticando con Wazuh: {login_response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Error extrayendo IPs de Wazuh: {e}")
            
        return list(set(ips))  # Eliminar duplicados
    
    def is_valid_ip(self, ip: str) -> bool:
        """Valida si una IP es válida"""
        try:
            parts = ip.split('.')
            return len(parts) == 4 and all(0 <= int(part) <= 255 for part in parts)
        except ValueError:
            return False
    
    def is_private_ip(self, ip: str) -> bool:
        """Verifica si una IP es privada"""
        try:
            parts = [int(x) for x in ip.split('.')]
            
            # Rangos de IPs privadas
            private_ranges = [
                (10, 0, 0, 0, 255, 255, 255, 255),
                (172, 16, 0, 0, 172, 31, 255, 255),
                (192, 168, 0, 0, 192, 168, 255, 255),
                (127, 0, 0, 0, 127, 255, 255, 255)
            ]
            
            for start in private_ranges:
                if (start[0] <= parts[0] <= start[4] and
                    start[1] <= parts[1] <= start[5] and
                    start[2] <= parts[2] <= start[6] and
                    start[3] <= parts[3] <= start[7]):
                    return True
                    
            return False
            
        except (ValueError, IndexError):
            return False
    
    def log_processed_ip(self, ip: str, source_log: str):
        """Registra una IP procesada en la base de datos"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO processed_ips (ip_address, source_log)
                VALUES (?, ?)
            ''', (ip, source_log))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Error registrando IP procesada: {e}")
    
    def is_ip_cached(self, ip: str) -> bool:
        """Verifica si una IP ya fue verificada recientemente"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Verificar si la IP fue actualizada dentro del período de cache
            cache_time = datetime.now() - timedelta(seconds=self.cache_duration)
            
            cursor.execute('''
                SELECT COUNT(*) FROM ip_reputation 
                WHERE ip_address = ? AND last_updated > ?
            ''', (ip, cache_time))
            
            count = cursor.fetchone()[0]
            conn.close()
            
            return count > 0
            
        except Exception as e:
            self.logger.error(f"Error verificando cache para IP {ip}: {e}")
            return False
    
    def check_virustotal(self, ip: str) -> Dict:
        """Verifica la reputación de una IP en VirusTotal"""
        if not self.virustotal_api_key:
            self.logger.warning("API key de VirusTotal no configurada")
            return {'detections': 0, 'total': 0}
        
        try:
            params = {
                'apikey': self.virustotal_api_key,
                'ip': ip
            }
            
            response = requests.get(self.virustotal_url, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('response_code') == 1:
                    detected_urls = data.get('detected_urls', [])
                    detected_samples = data.get('detected_communicating_samples', [])
                    
                    # Contar detecciones
                    url_detections = len(detected_urls)
                    sample_detections = len(detected_samples)
                    
                    total_detections = url_detections + sample_detections
                    
                    return {
                        'detections': total_detections,
                        'total': total_detections,
                        'detected_urls': url_detections,
                        'detected_samples': sample_detections
                    }
                else:
                    return {'detections': 0, 'total': 0}
                    
            elif response.status_code == 204:
                self.logger.warning("Límite de API de VirusTotal alcanzado")
                return {'detections': 0, 'total': 0}
            else:
                self.logger.error(f"Error en VirusTotal para IP {ip}: {response.status_code}")
                return {'detections': 0, 'total': 0}
                
        except Exception as e:
            self.logger.error(f"Error consultando VirusTotal para IP {ip}: {e}")
            return {'detections': 0, 'total': 0}
    
    def check_abuseipdb(self, ip: str) -> Dict:
        """Verifica la reputación de una IP en AbuseIPDB"""
        if not self.abuseipdb_api_key:
            self.logger.warning("API key de AbuseIPDB no configurada")
            return {'confidence': 0, 'usage_type': '', 'country_code': ''}
        
        try:
            headers = {
                'Key': self.abuseipdb_api_key,
                'Accept': 'application/json'
            }
            
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 90,
                'verbose': ''
            }
            
            response = requests.get(self.abuseipdb_url, headers=headers, params=params, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                if 'data' in data:
                    result = data['data']
                    return {
                        'confidence': result.get('abuseConfidencePercentage', 0),
                        'usage_type': result.get('usageType', ''),
                        'country_code': result.get('countryCode', ''),
                        'is_whitelisted': result.get('isWhitelisted', False)
                    }
                else:
                    return {'confidence': 0, 'usage_type': '', 'country_code': ''}
                    
            elif response.status_code == 429:
                self.logger.warning("Límite de API de AbuseIPDB alcanzado")
                return {'confidence': 0, 'usage_type': '', 'country_code': ''}
            else:
                self.logger.error(f"Error en AbuseIPDB para IP {ip}: {response.status_code}")
                return {'confidence': 0, 'usage_type': '', 'country_code': ''}
                
        except Exception as e:
            self.logger.error(f"Error consultando AbuseIPDB para IP {ip}: {e}")
            return {'confidence': 0, 'usage_type': '', 'country_code': ''}
    
    def analyze_ip_reputation(self, ip: str) -> Dict:
        """Analiza la reputación completa de una IP"""
        self.logger.info(f"Analizando reputación de IP: {ip}")
        
        # Verificar VirusTotal
        vt_result = self.check_virustotal(ip)
        time.sleep(1)  # Respetar límites de API
        
        # Verificar AbuseIPDB
        abuse_result = self.check_abuseipdb(ip)
        time.sleep(1)  # Respetar límites de API
        
        # Determinar si es maliciosa o sospechosa
        is_malicious = (vt_result['detections'] >= self.malicious_threshold or
                       abuse_result['confidence'] >= self.abuse_confidence_threshold)
        
        is_suspicious = (vt_result['detections'] >= self.suspicious_threshold or
                        abuse_result['confidence'] >= 50)
        
        result = {
            'ip': ip,
            'virustotal_detections': vt_result['detections'],
            'virustotal_total': vt_result['total'],
            'abuseipdb_confidence': abuse_result['confidence'],
            'abuseipdb_usage_type': abuse_result['usage_type'],
            'country_code': abuse_result['country_code'],
            'is_malicious': is_malicious,
            'is_suspicious': is_suspicious,
            'timestamp': datetime.now()
        }
        
        return result
    
    def save_reputation_result(self, result: Dict):
        """Guarda el resultado de reputación en la base de datos"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Verificar si ya existe
            cursor.execute('SELECT id FROM ip_reputation WHERE ip_address = ?', (result['ip'],))
            existing = cursor.fetchone()
            
            if existing:
                # Actualizar
                cursor.execute('''
                    UPDATE ip_reputation SET
                        virustotal_detections = ?,
                        virustotal_total = ?,
                        abuseipdb_confidence = ?,
                        abuseipdb_usage_type = ?,
                        country_code = ?,
                        is_malicious = ?,
                        is_suspicious = ?,
                        last_updated = ?
                    WHERE ip_address = ?
                ''', (
                    result['virustotal_detections'],
                    result['virustotal_total'],
                    result['abuseipdb_confidence'],
                    result['abuseipdb_usage_type'],
                    result['country_code'],
                    result['is_malicious'],
                    result['is_suspicious'],
                    result['timestamp'],
                    result['ip']
                ))
            else:
                # Insertar
                cursor.execute('''
                    INSERT INTO ip_reputation (
                        ip_address, virustotal_detections, virustotal_total,
                        abuseipdb_confidence, abuseipdb_usage_type, country_code,
                        is_malicious, is_suspicious, last_updated
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result['ip'],
                    result['virustotal_detections'],
                    result['virustotal_total'],
                    result['abuseipdb_confidence'],
                    result['abuseipdb_usage_type'],
                    result['country_code'],
                    result['is_malicious'],
                    result['is_suspicious'],
                    result['timestamp']
                ))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"Resultado guardado para IP {result['ip']}")
            
        except Exception as e:
            self.logger.error(f"Error guardando resultado para IP {result['ip']}: {e}")
    
    def send_alert(self, ip: str, result: Dict):
        """Envía alerta por email para IPs maliciosas"""
        if not self.email_config['enabled']:
            return
            
        try:
            # Verificar si ya se envió alerta para esta IP
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT COUNT(*) FROM sent_alerts 
                WHERE ip_address = ? AND sent_at > datetime('now', '-24 hours')
            ''', (ip,))
            
            recent_alerts = cursor.fetchone()[0]
            
            if recent_alerts > 0:
                self.logger.info(f"Alerta ya enviada para IP {ip} en las últimas 24 horas")
                conn.close()
                return
            
            # Crear mensaje de alerta
            subject = f"🚨 IP Maliciosa Detectada: {ip}"
            
            if result['is_malicious']:
                alert_type = "MALICIOSA"
                priority = "ALTA"
            else:
                alert_type = "SOSPECHOSA"
                priority = "MEDIA"
            
            body = f"""
            ALERTA DE SEGURIDAD - IP {alert_type}
            
            IP Address: {ip}
            Prioridad: {priority}
            País: {result['country_code']}
            Tipo de Uso: {result['abuseipdb_usage_type']}
            
            DETALLES DE REPUTACIÓN:
            - VirusTotal Detecciones: {result['virustotal_detections']}/{result['virustotal_total']}
            - AbuseIPDB Confianza: {result['abuseipdb_confidence']}%
            
            Esta IP ha sido detectada en los logs de Wazuh y presenta indicadores de actividad maliciosa.
            
            Recomendaciones:
            1. Revisar logs relacionados con esta IP
            2. Considerar bloquear la IP en el firewall
            3. Investigar posibles compromisos en sistemas que interactuaron con esta IP
            
            Timestamp: {result['timestamp']}
            
            Sistema: Wazuh IP Reputation Checker
            """
            
            # Enviar email
            msg = MIMEMultipart()
            msg['From'] = self.email_config['from_email']
            msg['To'] = ', '.join(self.email_config['to_emails'])
            msg['Subject'] = subject
            
            msg.attach(MIMEText(body, 'plain'))
            
            server = smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port'])
            
            if self.email_config['username'] and self.email_config['password']:
                server.starttls()
                server.login(self.email_config['username'], self.email_config['password'])
            
            server.send_message(msg)
            server.quit()
            
            # Registrar alerta enviada
            cursor.execute('''
                INSERT INTO sent_alerts (ip_address, alert_type, alert_content)
                VALUES (?, ?, ?)
            ''', (ip, alert_type, body))
            
            conn.commit()
            conn.close()
            
            self.logger.info(f"Alerta enviada para IP {ip}")
            
        except Exception as e:
            self.logger.error(f"Error enviando alerta para IP {ip}: {e}")
    
    def run_analysis(self):
        """Ejecuta el análisis completo de reputación de IPs"""
        self.logger.info("Iniciando análisis de reputación de IPs")
        
        # Extraer IPs de Wazuh
        ips = self.extract_ips_from_logs()
        
        if not ips:
            self.logger.info("No se encontraron IPs para analizar")
            return
        
        processed_count = 0
        malicious_count = 0
        suspicious_count = 0
        
        for ip in ips:
            try:
                # Verificar si la IP está en cache
                if self.is_ip_cached(ip):
                    self.logger.debug(f"IP {ip} en cache, omitiendo análisis")
                    continue
                
                # Analizar reputación
                result = self.analyze_ip_reputation(ip)
                
                # Guardar resultado
                self.save_reputation_result(result)
                
                # Enviar alerta si es necesario
                if result['is_malicious'] or result['is_suspicious']:
                    self.send_alert(ip, result)
                
                # Estadísticas
                processed_count += 1
                if result['is_malicious']:
                    malicious_count += 1
                elif result['is_suspicious']:
                    suspicious_count += 1
                
                self.logger.info(f"IP {ip}: VT={result['virustotal_detections']}, "
                               f"Abuse={result['abuseipdb_confidence']}%, "
                               f"Maliciosa={result['is_malicious']}, "
                               f"Sospechosa={result['is_suspicious']}")
                
            except Exception as e:
                self.logger.error(f"Error procesando IP {ip}: {e}")
        
        self.logger.info(f"Análisis completado: {processed_count} IPs procesadas, "
                        f"{malicious_count} maliciosas, {suspicious_count} sospechosas")
    
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
                time.sleep(60)  # Esperar 1 minuto antes de reintentar

def main():
    """Función principal"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Wazuh IP Reputation Checker')
    parser.add_argument('--config', default='/opt/wazuh-ip-reputation/config',
                       help='Archivo de configuración')
    parser.add_argument('--once', action='store_true',
                       help='Ejecutar análisis una sola vez')
    parser.add_argument('--continuous', action='store_true',
                       help='Ejecutar análisis continuo')
    
    args = parser.parse_args()
    
    # Verificar que el archivo de configuración existe
    if not os.path.exists(args.config):
        print(f"Error: Archivo de configuración no encontrado: {args.config}")
        sys.exit(1)
    
    # Crear instancia del checker
    checker = WazuhIPReputationChecker(args.config)
    
    if args.once:
        checker.run_analysis()
    elif args.continuous:
        checker.run_continuous()
    else:
        print("Uso: python3 wazuh_ip_reputation.py --once | --continuous")
        print("Use --help para más información")
        sys.exit(1)

if __name__ == "__main__":
    main()
