# Wazuh IP Reputation Checker

Sistema automatizado para verificar la reputación de direcciones IP encontradas en los logs de Wazuh utilizando VirusTotal y AbuseIPDB.

## Características

- **Análisis automático**: Extrae IPs de los logs de Wazuh y verifica su reputación
- **Múltiples fuentes**: Utiliza VirusTotal y AbuseIPDB para verificación
- **Alertas automáticas**: Envía notificaciones por email para IPs maliciosas
- **Base de datos**: Almacena resultados en SQLite para análisis histórico
- **Cache inteligente**: Evita consultas repetitivas a las APIs
- **Monitoreo continuo**: Ejecuta verificaciones de forma automática
- **Fácil despliegue**: Script de instalación automatizado

## Requisitos del Sistema

- Ubuntu 22.04 LTS
- Python 3.10+
- Acceso a Wazuh Manager API
- Conexión a internet para APIs externas
- Privilegios de administrador para instalación

## Instalación

### 1. Descarga e Instalación

```bash
# Descargar el proyecto
git clone https://github.com/your-repo/wazuh-ip-reputation.git
cd wazuh-ip-reputation

# Ejecutar instalación
sudo chmod +x install.sh
sudo ./install.sh
```

### 2. Configuración

Editar el archivo de configuración:

```bash
sudo nano /opt/wazuh-ip-reputation/config
```

#### Configuración de APIs

**VirusTotal API Key:**
1. Registrarse en https://www.virustotal.com/
2. Obtener API key desde https://www.virustotal.com/gui/my-apikey
3. Configurar en el archivo config:
   ```ini
   [apis]
   virustotal_key = YOUR_VIRUSTOTAL_API_KEY_HERE
   ```

**AbuseIPDB API Key:**
1. Registrarse en https://www.abuseipdb.com/
2. Obtener API key desde https://www.abuseipdb.com/account/api
3. Configurar en el archivo config:
   ```ini
   [apis]
   abuseipdb_key = YOUR_ABUSEIPDB_API_KEY_HERE
   ```

#### Configuración de Wazuh

```ini
[wazuh]
host = YOUR_WAZUH_MANAGER_IP
port = 55000
username = wazuh-user
password = wazuh-password
verify_ssl = false
```

#### Configuración de Email

```ini
[email]
enabled = true
smtp_server = smtp.gmail.com
smtp_port = 587
username = your_email@gmail.com
password = your_app_password
from_email = wazuh-alerts@yourdomain.com
to_emails = admin@yourdomain.com,security@yourdomain.com
```

### 3. Iniciar el Servicio

```bash
# Iniciar servicio
sudo systemctl start wazuh-ip-reputation

# Habilitar inicio automático
sudo systemctl enable wazuh-ip-reputation

# Verificar estado
sudo systemctl status wazuh-ip-reputation
```

## Uso

### Comandos Básicos

```bash
# Ver logs del servicio
sudo journalctl -u wazuh-ip-reputation -f

# Ejecutar análisis único
sudo -u wazuh-reputation /opt/wazuh-ip-reputation/venv/bin/python3 /opt/wazuh-ip-reputation/wazuh_ip_reputation.py --once

# Reiniciar servicio
sudo systemctl restart wazuh-ip-reputation

# Detener servicio
sudo systemctl stop wazuh-ip-reputation
```

### Backup Manual

```bash
sudo -u wazuh-reputation /opt/wazuh-ip-reputation/backup.sh
```

### Monitoreo Manual

```bash
sudo -u wazuh-reputation /opt/wazuh-ip-reputation/monitor.sh
```

## Estructura de Archivos

```
/opt/wazuh-ip-reputation/
├── wazuh_ip_reputation.py    # Script principal
├── config                    # Configuración
├── config.default            # Configuración por defecto
├── ip_reputation.db          # Base de datos SQLite
├── backup.sh                 # Script de backup
├── monitor.sh                # Script de monitoreo
├── venv/                     # Entorno virtual Python
├── logs/                     # Logs del sistema
└── backup/                   # Backups de la base de datos
```

## Base de Datos

### Tablas

1. **ip_reputation**: Resultados de análisis de reputación
2. **sent_alerts**: Registro de alertas enviadas
3. **processed_ips**: Log de IPs procesadas

### Consultas Útiles

```sql
-- IPs maliciosas detectadas
SELECT * FROM ip_reputation WHERE is_malicious = 1;

-- IPs con alta confianza de abuso
SELECT * FROM ip_reputation WHERE abuseipdb_confidence > 75;

-- Estadísticas por país
SELECT country_code, COUNT(*) as count 
FROM ip_reputation 
WHERE is_malicious = 1 
GROUP BY country_code;

-- Alertas enviadas hoy
SELECT * FROM sent_alerts 
WHERE DATE(sent_at) = DATE('now');
```

## Configuración Avanzada

### Umbrales de Detección

```ini
[thresholds]
# Número de detecciones en VirusTotal para considerar maliciosa
malicious_threshold = 5

# Número de detecciones para considerar sospechosa
suspicious_threshold = 2

# Porcentaje de confianza en AbuseIPDB
abuse_confidence_threshold = 75
```

### Intervalos de Verificación

```ini
[general]
# Intervalo entre verificaciones (segundos)
check_interval = 300

# Duración del cache (segundos)
cache_duration = 3600

# Nivel de logging
log_level = INFO
```

## Monitoreo y Alertas

### Tipos de Alertas

1. **IP Maliciosa**: Alta confianza de actividad maliciosa
2. **IP Sospechosa**: Indicadores de actividad sospechosa

### Contenido de Alertas

- Dirección IP
- Nivel de prioridad
- País de origen
- Tipo de uso reportado
- Puntuaciones de reputación
- Recomendaciones de acción

## Solución de Problemas

### Problemas Comunes

1. **Error de autenticación con Wazuh**
   ```bash
   # Verificar credenciales en config
   sudo nano /opt/wazuh-ip-reputation/config
   
   # Verificar conectividad
   curl -k https://WAZUH_HOST:55000/security/user/authenticate
   ```

2. **APIs no responden**
   ```bash
   # Verificar conectividad
   curl -v https://www.virustotal.com/vtapi/v2/ip-address/report
   curl -v https://api.abuseipdb.com/api/v2/check
   ```

3. **Servicio no inicia**
   ```bash
   # Ver logs detallados
   sudo journalctl -u wazuh-ip-reputation -n 50
   
   # Verificar permisos
   sudo ls -la /opt/wazuh-ip-reputation/
   ```

### Logs Importantes

- **Servicio**: `sudo journalctl -u wazuh-ip-reputation`
- **Aplicación**: `/var/log/wazuh-ip-reputation.log`
- **Backup**: `/var/log/wazuh-ip-reputation-backup.log`
- **Monitoreo**: `/var/log/wazuh-ip-reputation-monitor.log`

## Mantenimiento

### Limpieza de Base de Datos

```bash
# Eliminar registros antiguos (30 días)
sqlite3 /opt/wazuh-ip-reputation/ip_reputation.db "DELETE FROM processed_ips WHERE processed_at < datetime('now', '-30 days');"

# Vaciar base de datos
sqlite3 /opt/wazuh-ip-reputation/ip_reputation.db "VACUUM;"
```

### Actualización

```bash
# Detener servicio
sudo systemctl stop wazuh-ip-reputation

# Backup de configuración
sudo cp /opt/wazuh-ip-reputation/config /opt/wazuh-ip-reputation/config.backup

# Actualizar código
# ... actualizar archivos ...

# Reiniciar servicio
sudo systemctl start wazuh-ip-reputation
```

## Seguridad

### Consideraciones

1. **Credenciales**: Almacenar de forma segura las API keys
2. **Permisos**: El servicio ejecuta con usuario limitado
3. **Red**: Configurar firewall para limitar acceso
4. **Logs**: Monitorear acceso a logs sensibles

### Hardening

```bash
# Permisos restrictivos en config
sudo chmod 600 /opt/wazuh-ip-reputation/config

# Verificar usuario del servicio
sudo id wazuh-reputation

# Verificar permisos de directorio
sudo ls -la /opt/wazuh-ip-reputation/
```

## Rendimiento

### Optimización

1. **Cache**: Ajustar `cache_duration` según necesidades
2. **Intervalos**: Configurar `check_interval` apropiadamente
3. **Límites**: Respetar límites de APIs externas
4. **Base de datos**: Limpiar registros antiguos regularmente

### Monitoreo de Recursos

```bash
# Uso de CPU y memoria
sudo ps aux | grep wazuh-ip-reputation

# Tamaño de base de datos
sudo du -h /opt/wazuh-ip-reputation/ip_reputation.db

# Logs de crecimiento
sudo tail -f /var/log/wazuh-ip-reputation-monitor.log
```

## Integración con Wazuh 
Reglas Personalizadas 
Crear reglas Wazuh para procesar alertas del sistema:
```xml
<group name="wazuh-ip-reputation">
  <rule id="100001" level="12">
    <program_name>wazuh-ip-reputation</program_name>
    <match>IP Maliciosa Detectada</match>
    <description>Malicious IP detected by reputation system</description>
  </rule>
</group>
```
Decoders
```xml
<decoder name="wazuh-ip-reputation">
  <program_name>wazuh-ip-reputation</program_name>
  <regex offset="after_parent">IP Address: (\S+) Priority: (\w+) Country: (\w+)</regex>
  <order>srcip,priority,country</order>
</decoder>
```
## API Limits y Costos
### VirusTotal
 - Gratis: 4 consultas/minuto, 500/día
 - Premium: 1000 consultas/minuto
 - Costo: Desde $4.99/mes

### AbuseIPDB
 - Gratis: 1000 consultas/día
 - Premium: 10,000+ consultas/día
 - Costo: Desde $20/mes

## Ejemplos de Uso
### Análisis de IP Específica
```bash# Verificar IP específica
sudo sqlite3 /opt/wazuh-ip-reputation/ip_reputation.db \
  "SELECT * FROM ip_reputation WHERE ip_address = '1.2.3.4';"
```
### Consulta de Estadísticas
```bash# IPs maliciosas por país
sudo sqlite3 /opt/wazuh-ip-reputation/ip_reputation.db \
  "SELECT country_code, COUNT(*) as malicious_count 
   FROM ip_reputation 
   WHERE is_malicious = 1 
   GROUP BY country_code 
   ORDER BY malicious_count DESC;"
```
### Exportar Resultados
```bash# Exportar a CSV
sudo sqlite3 -header -csv /opt/wazuh-ip-reputation/ip_reputation.db \
  "SELECT * FROM ip_reputation WHERE is_malicious = 1;" > malicious_ips.csv
```
### Troubleshooting Avanzado
Debug Mode
Activar modo debug modificando el config:
```ini[general]
log_level = DEBUG
```
Verificación Manual de APIs
```bash# Test VirusTotal
curl -X GET "https://www.virustotal.com/vtapi/v2/ip-address/report?apikey=YOUR_KEY&ip=8.8.8.8"

# Test AbuseIPDB
curl -G https://api.abuseipdb.com/api/v2/check \
  --data-urlencode "ipAddress=8.8.8.8" \
  -H "Key: YOUR_KEY" \
  -H "Accept: application/json"
```
Validación de Base de Datos
```bash# Verificar integridad
sudo sqlite3 /opt/wazuh-ip-reputation/ip_reputation.db "PRAGMA integrity_check;"

# Estadísticas de la BD
sudo sqlite3 /opt/wazuh-ip-reputation/ip_reputation.db ".schema"
```
### Personalización
Agregar Nuevas Fuentes de Threat Intelligence
El sistema puede extenderse para incluir nuevas fuentes:

Shodan: Para información de dispositivos
URLVoid: Para análisis de URLs
IBM X-Force: Para inteligencia de amenazas
Hybrid Analysis: Para análisis de malware

### Custom Scoring
Implementar sistema de puntuación personalizado:
pythondef calculate_custom_score(vt_detections, abuse_confidence, country_risk):
    base_score = (vt_detections * 10) + abuse_confidence
    
    # Ajustar por país de alto riesgo
    if country_risk == 'HIGH':
        base_score *= 1.5
    
    return min(base_score, 100)

### Integración con SIEM
#### Splunk
```bash# Configurar input para Splunk
[monitor:///var/log/wazuh-ip-reputation.log]
disabled = false
sourcetype = wazuh_ip_reputation
index = security
```
#### ELK Stack
```yaml# Logstash configuration
input {
  file {
    path => "/var/log/wazuh-ip-reputation.log"
    type => "wazuh-ip-reputation"
  }
}

filter {
  if [type] == "wazuh-ip-reputation" {
    grok {
      match => { "message" => "%{TIMESTAMP_ISO8601:timestamp} - %{LOGLEVEL:level} - IP %{IP:ip_address}: VT=%{NUMBER:vt_detections}" }
    }
  }
}
```
### Compliance y Reportes
#### Generación de Reportes
```bash# Reporte diario
sudo sqlite3 -header /opt/wazuh-ip-reputation/ip_reputation.db \
  "SELECT 
     DATE(last_updated) as date,
     COUNT(*) as total_ips,
     SUM(CASE WHEN is_malicious = 1 THEN 1 ELSE 0 END) as malicious,
     SUM(CASE WHEN is_suspicious = 1 THEN 1 ELSE 0 END) as suspicious
   FROM ip_reputation 
   WHERE DATE(last_updated) = DATE('now')
   GROUP BY DATE(last_updated);"
```
### Métricas de Seguridad
 - MTTR (Mean Time To Response): Tiempo desde detección hasta alerta \
 - FPR (False Positive Rate): Tasa de falsos positivos \
 - Coverage: Porcentaje de IPs analizadas vs. total en logs

### Backup y Recuperación
Estrategia de Backup

Diario: Base de datos y configuración
Semanal: Logs históricos
Mensual: Backup completo del sistema

Script de Recuperación
```bash#!/bin/bash
# restore.sh

BACKUP_DATE=$1
BACKUP_DIR="/opt/wazuh-ip-reputation/backup"

if [[ -z "$BACKUP_DATE" ]]; then
    echo "Uso: $0 YYYYMMDD_HHMMSS"
    exit 1
fi

# Detener servicio
systemctl stop wazuh-ip-reputation

# Restaurar base de datos
cp "$BACKUP_DIR/ip_reputation_${BACKUP_DATE}.db" \
   "/opt/wazuh-ip-reputation/ip_reputation.db"

# Restaurar configuración
cp "$BACKUP_DIR/config_${BACKUP_DATE}" \
   "/opt/wazuh-ip-reputation/config"

# Reiniciar servicio
systemctl start wazuh-ip-reputation

echo "Restauración completada para $BACKUP_DATE"
```
### Mejores Prácticas

#### Operación

Monitoreo: Revisar logs diariamente
Mantenimiento: Limpiar BD semanalmente
Actualizaciones: Mantener APIs keys actualizadas
Testing: Probar alertas mensualmente

#### Seguridad

Rotación: Rotar API keys trimestralmente
Acceso: Limitar acceso a archivos de configuración
Auditoría: Revisar logs de acceso regularmente
Encryption: Considerar cifrado de base de datos

#### Rendimiento

Caching: Ajustar cache según volumen
 - Batching: Procesar IPs en lotes
 - Throttling: Respetar límites de API
 - Indexing: Mantener índices optimizados

### Roadmap y Futuras Mejoras
Próximas Versiones

 - v1.1: Interfaz web para monitoreo
 - v1.2: Integración con más fuentes TI
 - v1.3: Machine Learning para detección
 - v1.4: API REST para integración

### Contribuciones
Para contribuir al proyecto:
[github](https://github.com/juanpadiaz/wazuh-ip-reputation) \
Fork del repositorio \
Crear branch para feature \
Implementar cambios \
Enviar Pull Request 

### Soporte
Canales de Soporte

GitHub Issues: Para bugs y features


### Información de Contacto

Desarrollador: juanpadiaz [jpdiaz.com](https://jpdiaz.com/)
Versión: 1.0.0
Licencia: LGPL-2.1 license
Última actualización: Julio 2025


Nota: Este sistema está diseñado para complementar, no reemplazar, las herramientas de seguridad existentes. Siempre valide los resultados y mantenga actualizadas las fuentes de threat intelligence.
