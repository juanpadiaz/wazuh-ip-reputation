#!/usr/bin/env python3
"""
Wazuh IP Reputation Checker
Analiza IPs de los logs de Wazuh usando VirusTotal y AbuseIPDB
"""

import json
import re
import time
import smtplib
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from pathlib import Path
from typing import Dict, List, Optional, Set
import requests
from configparser import ConfigParser

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('wazuh_ip_reputation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

class WazuhIPReputationChecker:
    def __init__(self, config_file: str = "config"):
        """Inicializa el checker con configuración desde archivo"""
        self.config = ConfigParser()
        self.config.read(config_file)
        
        # Configuración de APIs
        self.virustotal_api_key = self.config.get('apis', 'virustotal_api_key')
        self.abuseipdb_api_key = self.config.get('apis', 'abuseipdb_api_key')
        
        # Configuración de Wazuh
        self.wazuh_url = self.config.get('wazuh', 'url')
        self.wazuh_username = self.config.get('wazuh', 'username')
        self.wazuh_password = self.config.get('wazuh', 'password')
        
        # Configuración de email
        self.smtp_server = self.config.get('email', 'smtp_server')
        self.smtp_port = self.config.getint('email', 'smtp_port')
        self.email_username = self.config.get('email', 'username')
        self.email_password = self.config.get('email', 'password')
        self.email_from = self.config.get('email', 'from_address')
        self.email_to = self.config.get('email', 'to_addresses').split(',')
        
        # Configuración general
        self.check_interval = self.config.getint('general', 'check_interval_minutes', fallback=30)
        self.virustotal_threshold = self.config.getint('general', 'virustotal_threshold', fallback=3)
        self.abuseipdb_threshold = self.config.getint('general', 'abuseipdb_threshold', fallback=25)
        
        # Cache para evitar consultas repetidas
        self.ip_cache = {}
        self.processed_ips = set()
        
        # Sesión para requests
        self.session = requests.Session()
        self.session.verify = self.config.getboolean('wazuh', 'ssl_verify', fallback=True)
        
        # Autenticación en Wazuh
        self.wazuh_token = self._authenticate_wazuh()
        
    def _authenticate_wazuh(self) -> str:
        """Autentica con Wazuh API y obtiene token"""
        try:
            auth_url = f"{self.wazuh_url}/security/user/authenticate"
            response = self.session.get(
                auth_url,
                auth=(self.wazuh_username, self.wazuh_password)
            )
            response.raise_for_status()
            token = response.json()['data']['token']
            self.session.headers.update({'Authorization': f'Bearer {token}'})
            logger.info("Autenticación exitosa con Wazuh")
            return token
        except Exception as e:
            logger.error(f"Error autenticando con Wazuh: {e}")
            raise
    
    def extract_ips_from_logs(self, hours_back: int = 1) -> Set[str]:
        """Extrae IPs de los logs de Wazuh de las últimas horas"""
        try:
            # Obtener alertas recientes
            alerts_url = f"{self.wazuh_url}/security/alerts"
            
            # Calcular timestamp para filtrar
            time_filter = datetime.now() - timedelta(hours=hours_back)
            timestamp = time_filter.strftime('%Y-%m-%dT%H:%M:%S')
            
            params = {
                'limit': 5000,
                'sort': '-timestamp',
                'timestamp': f'>{timestamp}'
            }
            
            response = self.session.get(alerts_url, params=params)
            response.raise_for_status()
            
            alerts = response.json().get('data', {}).get('affected_items', [])
            
            # Extraer IPs de los logs
            ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            ips = set()
            
            for alert in alerts:
                # Buscar IPs en diferentes campos
                fields_to_check = [
                    'data.srcip', 'data.dstip', 'data.src_ip', 'data.dst_ip',
                    'data.url', 'full_log', 'data.data'
                ]
                
                for field in fields_to_check:
                    value = self._get_nested_value(alert, field)
                    if value:
                        found_ips = re.findall(ip_pattern, str(value))
                        ips.update(found_ips)
            
            # Filtrar IPs privadas
            ips = {ip for ip in ips if self._is_public_ip(ip)}
            
            logger.info(f"Extraídas {len(ips)} IPs únicas de los logs")
            return ips
            
        except Exception as e:
            logger.error(f"Error extrayendo IPs de los logs: {e}")
            return set()
    
    def _get_nested_value(self, data: dict, path: str):
        """Obtiene valor anidado usando notación de puntos"""
        try:
            keys = path.split('.')
            value = data
            for key in keys:
                if isinstance(value, dict) and key in value:
                    value = value[key]
                else:
                    return None
            return value
        except:
            return None
    
    def _is_public_ip(self, ip: str) -> bool:
        """Verifica si una IP es pública (no privada)"""
        try:
            parts = [int(x) for x in ip.split('.')]
            
            # Rangos privados
            private_ranges = [
                (10, 0, 0, 0, 10, 255, 255, 255),      # 10.0.0.0/8
                (172, 16, 0, 0, 172, 31, 255, 255),    # 172.16.0.0/12
                (192, 168, 0, 0, 192, 168, 255, 255),  # 192.168.0.0/16
                (127, 0, 0, 0, 127, 255, 255, 255),    # 127.0.0.0/8
                (169, 254, 0, 0, 169, 254, 255, 255),  # 169.254.0.0/16
            ]
            
            for start_a, start_b, start_c, start_d, end_a, end_b, end_c, end_d in private_ranges:
                if (start_a <= parts[0] <= end_a and
                    start_b <= parts[1] <= end_b and
                    start_c <= parts[2] <= end_c and
                    start_d <= parts[3] <= end_d):
                    return False
            
            return True
        except:
            return False
    
    def check_virustotal(self, ip: str) -> Dict:
        """Consulta reputación en VirusTotal"""
        if not self.virustotal_api_key:
            return {'error': 'API key no configurada'}
        
        try:
            url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
            params = {
                'apikey': self.virustotal_api_key,
                'ip': ip
            }
            
            response = requests.get(url, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('response_code') == 1:
                positives = data.get('positives', 0)
                total = data.get('total', 0)
                
                return {
                    'ip': ip,
                    'positives': positives,
                    'total': total,
                    'malicious': positives >= self.virustotal_threshold,
                    'detected_urls': data.get('detected_urls', [])[:5],  # Solo primeras 5
                    'source': 'VirusTotal'
                }
            else:
                return {'ip': ip, 'error': 'IP no encontrada en VirusTotal'}
                
        except Exception as e:
            logger.error(f"Error consultando VirusTotal para {ip}: {e}")
            return {'ip': ip, 'error': str(e)}
    
    def check_abuseipdb(self, ip: str) -> Dict:
        """Consulta reputación en AbuseIPDB"""
        if not self.abuseipdb_api_key:
            return {'error': 'API key no configurada'}
        
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
            
            response = requests.get(url, headers=headers, params=params)
            response.raise_for_status()
            
            data = response.json()
            
            if 'data' in data:
                abuse_confidence = data['data'].get('abuseConfidencePercentage', 0)
                
                return {
                    'ip': ip,
                    'abuse_confidence': abuse_confidence,
                    'malicious': abuse_confidence >= self.abuseipdb_threshold,
                    'country': data['data'].get('countryCode', 'Unknown'),
                    'usage_type': data['data'].get('usageType', 'Unknown'),
                    'isp': data['data'].get('isp', 'Unknown'),
                    'total_reports': data['data'].get('totalReports', 0),
                    'source': 'AbuseIPDB'
                }
            else:
                return {'ip': ip, 'error': 'IP no encontrada en AbuseIPDB'}
                
        except Exception as e:
            logger.error(f"Error consultando AbuseIPDB para {ip}: {e}")
            return {'ip': ip, 'error': str(e)}
    
    def check_ip_reputation(self, ip: str) -> Dict:
        """Consulta reputación completa de una IP"""
        if ip in self.ip_cache:
            return self.ip_cache[ip]
        
        logger.info(f"Verificando reputación de {ip}")
        
        # Consultar ambas fuentes
        vt_result = self.check_virustotal(ip)
        time.sleep(1)  # Rate limiting
        
        abuse_result = self.check_abuseipdb(ip)
        time.sleep(1)  # Rate limiting
        
        # Combinar resultados
        result = {
            'ip': ip,
            'timestamp': datetime.now().isoformat(),
            'virustotal': vt_result,
            'abuseipdb': abuse_result,
            'malicious': False,
            'risk_score': 0
        }
        
        # Calcular riesgo
        risk_score = 0
        reasons = []
        
        if vt_result.get('malicious'):
            risk_score += 50
            reasons.append(f"VirusTotal: {vt_result['positives']}/{vt_result['total']} detectores")
        
        if abuse_result.get('malicious'):
            risk_score += 50
            reasons.append(f"AbuseIPDB: {abuse_result['abuse_confidence']}% confianza de abuso")
        
        result['risk_score'] = risk_score
        result['reasons'] = reasons
        result['malicious'] = risk_score >= 50
        
        # Cachear resultado
        self.ip_cache[ip] = result
        
        return result
    
    def send_alert_email(self, malicious_ips: List[Dict]):
        """Envía alerta por email"""
        try:
            msg = MIMEMultipart()
            msg['From'] = self.email_from
            msg['To'] = ', '.join(self.email_to)
            msg['Subject'] = f"🚨 Wazuh IP Reputation Alert - {len(malicious_ips)} IPs maliciosas detectadas"
            
            # Crear cuerpo del email
            body = self._create_email_body(malicious_ips)
            msg.attach(MIMEText(body, 'html'))
            
            # Enviar email
            server = smtplib.SMTP(self.smtp_server, self.smtp_port)
            server.starttls()
            server.login(self.email_username, self.email_password)
            server.send_message(msg)
            server.quit()
            
            logger.info(f"Alerta enviada por email a {len(self.email_to)} destinatarios")
            
        except Exception as e:
            logger.error(f"Error enviando email: {e}")
    
    def _create_email_body(self, malicious_ips: List[Dict]) -> str:
        """Crea el cuerpo HTML del email de alerta"""
        html = f"""
        <html>
        <body>
            <h2>🚨 Alerta de Reputación de IPs - Wazuh</h2>
            <p><strong>Fecha:</strong> {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
            <p><strong>IPs maliciosas detectadas:</strong> {len(malicious_ips)}</p>
            
            <table border="1" style="border-collapse: collapse; width: 100%;">
                <thead>
                    <tr style="background-color: #f2f2f2;">
                        <th>IP</th>
                        <th>Riesgo</th>
                        <th>VirusTotal</th>
                        <th>AbuseIPDB</th>
                        <th>País</th>
                        <th>Razones</th>
                    </tr>
                </thead>
                <tbody>
        """
        
        for ip_data in malicious_ips:
            vt = ip_data.get('virustotal', {})
            abuse = ip_data.get('abuseipdb', {})
            
            vt_info = f"{vt.get('positives', 0)}/{vt.get('total', 0)}" if 'positives' in vt else "N/A"
            abuse_info = f"{abuse.get('abuse_confidence', 0)}%" if 'abuse_confidence' in abuse else "N/A"
            country = abuse.get('country', 'Unknown')
            reasons = '<br>'.join(ip_data.get('reasons', []))
            
            html += f"""
                <tr>
                    <td>{ip_data['ip']}</td>
                    <td>{ip_data['risk_score']}</td>
                    <td>{vt_info}</td>
                    <td>{abuse_info}</td>
                    <td>{country}</td>
                    <td>{reasons}</td>
                </tr>
            """
        
        html += """
                </tbody>
            </table>
            
            <p><strong>Recomendaciones:</strong></p>
            <ul>
                <li>Revisar logs de Wazuh para estas IPs</li>
                <li>Considerar bloquear estas IPs en firewall</li>
                <li>Investigar posibles compromisos de seguridad</li>
            </ul>
            
            <p><em>Este es un mensaje automático del sistema de monitoreo de Wazuh.</em></p>
        </body>
        </html>
        """
        
        return html
    
    def save_results(self, results: List[Dict]):
        """Guarda resultados en archivo JSON"""
        try:
            output_file = f"ip_reputation_results_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(output_file, 'w') as f:
                json.dump(results, f, indent=2, ensure_ascii=False)
            logger.info(f"Resultados guardados en {output_file}")
        except Exception as e:
            logger.error(f"Error guardando resultados: {e}")
    
    def run_check(self):
        """Ejecuta verificación completa"""
        try:
            logger.info("Iniciando verificación de reputación de IPs...")
            
            # Extraer IPs de logs
            ips = self.extract_ips_from_logs(hours_back=1)
            
            if not ips:
                logger.info("No se encontraron IPs para verificar")
                return
            
            # Verificar solo IPs nuevas
            new_ips = ips - self.processed_ips
            if not new_ips:
                logger.info("No hay IPs nuevas para verificar")
                return
            
            logger.info(f"Verificando {len(new_ips)} IPs nuevas...")
            
            # Verificar reputación
            results = []
            malicious_ips = []
            
            for ip in new_ips:
                result = self.check_ip_reputation(ip)
                results.append(result)
                
                if result['malicious']:
                    malicious_ips.append(result)
                    logger.warning(f"IP maliciosa detectada: {ip} (Riesgo: {result['risk_score']})")
                
                # Marcar como procesada
                self.processed_ips.add(ip)
            
            # Enviar alertas si hay IPs maliciosas
            if malicious_ips:
                self.send_alert_email(malicious_ips)
                logger.info(f"Enviada alerta para {len(malicious_ips)} IPs maliciosas")
            
            # Guardar resultados
            self.save_results(results)
            
            logger.info(f"Verificación completada. {len(malicious_ips)} IPs maliciosas de {len(results)} verificadas")
            
        except Exception as e:
            logger.error(f"Error en verificación: {e}")
    
    def run_continuous(self):
        """Ejecuta verificación continua"""
        logger.info(f"Iniciando monitoreo continuo cada {self.check_interval} minutos...")
        
        while True:
            try:
                self.run_check()
                
                # Limpiar cache periodicamente
                if len(self.ip_cache) > 1000:
                    self.ip_cache.clear()
                    logger.info("Cache de IPs limpiado")
                
                # Esperar intervalo
                time.sleep(self.check_interval * 60)
                
            except KeyboardInterrupt:
                logger.info("Monitoreo detenido por usuario")
                break
            except Exception as e:
                logger.error(f"Error en monitoreo continuo: {e}")
                time.sleep(60)  # Esperar 1 minuto antes de reintentar

def main():
    """Función principal"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Wazuh IP Reputation Checker')
    parser.add_argument('--config', default='config', help='Archivo de configuración')
    parser.add_argument('--once', action='store_true', help='Ejecutar solo una vez')
    parser.add_argument('--continuous', action='store_true', help='Ejecutar continuamente')
    
    args = parser.parse_args()
    
    # Verificar archivo de configuración
    if not Path(args.config).exists():
        logger.error(f"Archivo de configuración no encontrado: {args.config}")
        return
    
    try:
        checker = WazuhIPReputationChecker(args.config)
        
        if args.once:
            checker.run_check()
        elif args.continuous:
            checker.run_continuous()
        else:
            # Por defecto, ejecutar una vez
            checker.run_check()
            
    except Exception as e:
        logger.error(f"Error iniciando aplicación: {e}")

if __name__ == "__main__":
    main()
