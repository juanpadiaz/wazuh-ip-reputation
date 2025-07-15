Sistema automático de verificación de reputación de IPs basado en logs de Wazuh, utilizando VirusTotal y AbuseIPDB para detectar IPs maliciosas y enviar alertas por correo electrónico.

Características.

✅ Extracción automática de IPs de logs de Wazuh

✅ Verificación de reputación usando VirusTotal y AbuseIPDB

✅ Alertas por email con información detallada

✅ Filtrado de IPs privadas (solo analiza IPs públicas)

Flujo Principal:

- Inicio y Configuración - Carga de configuración y autenticación
- Modos de Ejecución - Una vez o modo continuo
- Extracción de IPs - Obtención de IPs desde logs de Wazuh
- Filtrado - Solo IPs públicas y nuevas
- Verificación de Reputación - Consultas a VirusTotal y AbuseIPDB
- Análisis de Riesgo - Cálculo de puntuación de riesgo
- Alertas - Envío de emails si hay IPs maliciosas
- Persistencia - Guardado de resultados en JSON

Conexiones Externas:

🌐 Wazuh Server (Puerto 55000) - API REST para obtener logs y alertas

🌐 VirusTotal API - Verificación de reputación de IPs

🌐 AbuseIPDB API - Consulta de reportes de abuso

📧 Servidor Email (Puerto 587/25) - Envío de alertas por SMTP

Características del Flujo:

- Rate Limiting - Esperas de 1 segundo entre consultas API
- Cache de IPs - Evita consultas repetidas
- Modo Continuo - Bucle de monitoreo con intervalos configurables
- Manejo de Errores - Logs y continuidad del servicio
- Filtrado Inteligente - Solo IPs públicas y nuevas

El diagrama está codificado por colores para facilitar la comprensión:

- Azul: Inicio/Fin
- Púrpura: Procesos
- Naranja: Decisiones
- Verde: Conexiones externas
- Rojo: Alertas y amenazas

```mermaid
graph TD
    A[🚀 Inicio de Aplicación] --> B[📋 Cargar Configuración]
    B --> C[🔐 Autenticación Wazuh API]
    C --> D{🔄 Modo de Ejecución}
    
    D -->|Una vez| E[📊 Ejecutar Verificación]
    D -->|Continuo| F[⏰ Bucle de Monitoreo]
    
    F --> G[⏳ Esperar Intervalo]
    G --> E
    
    E --> H[📜 Extraer IPs de Logs Wazuh]
    H --> I[🔍 Filtrar IPs Públicas]
    I --> J{📝 ¿IPs Nuevas?}
    
    J -->|No| K[📋 Log: No hay IPs nuevas]
    J -->|Sí| L[🔄 Procesar cada IP]
    
    L --> M[🦠 Consultar VirusTotal]
    M --> N[⏱️ Esperar 1 segundo]
    N --> O[🚨 Consultar AbuseIPDB]
    O --> P[⏱️ Esperar 1 segundo]
    P --> Q[🧮 Calcular Riesgo]
    
    Q --> R{⚠️ ¿IP Maliciosa?}
    R -->|Sí| S[📝 Agregar a Lista Maliciosas]
    R -->|No| T[📝 Marcar como Procesada]
    
    S --> T
    T --> U{🔄 ¿Más IPs?}
    U -->|Sí| L
    U -->|No| V{📧 ¿Hay IPs Maliciosas?}
    
    V -->|Sí| W[📧 Enviar Alerta Email]
    V -->|No| X[📋 Log: No hay amenazas]
    
    W --> Y[💾 Guardar Resultados JSON]
    X --> Y
    Y --> Z[📋 Log: Verificación Completada]
    
    Z --> AA{🔄 ¿Modo Continuo?}
    AA -->|Sí| F
    AA -->|No| BB[🏁 Fin]
    
    K --> AA
    
    %% Conexiones externas
    C -.->|HTTPS| C1[🌐 Wazuh Server<br/>Puerto 55000]
    H -.->|API REST| C1
    M -.->|HTTPS| C2[🌐 VirusTotal API<br/>www.virustotal.com]
    O -.->|HTTPS| C3[🌐 AbuseIPDB API<br/>api.abuseipdb.com]
    W -.->|SMTP| C4[📧 Servidor Email<br/>Puerto 587/25]
    
    %% Estilos
    classDef startEnd fill:#e1f5fe,stroke:#0277bd,stroke-width:2px
    classDef process fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef decision fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef external fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px
    classDef alert fill:#ffebee,stroke:#c62828,stroke-width:2px
    
    class A,BB startEnd
    class B,C,E,H,I,L,M,N,O,P,Q,S,T,W,X,Y,Z,K process
    class D,J,R,U,V,AA decision
    class C1,C2,C3,C4 external
    class S,W alert
    class F,G process
```
