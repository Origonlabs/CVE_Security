# 🌐 Referencia de API REST

## 🎯 Endpoints Principales

### Autenticación
```http
POST /api/v1/auth/login
Content-Type: application/json

{
  "username": "user@company.com",
  "password": "password",
  "provider": "oidc"
}

Response:
{
  "access_token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9...",
  "token_type": "bearer",
  "expires_in": 3600,
  "refresh_token": "refresh_token_here"
}
```

### Gestión de Scans

#### Iniciar Scan
```http
POST /api/v1/scans
Authorization: Bearer {token}
Content-Type: application/json

{
  "repository": {
    "type": "git",
    "url": "https://github.com/user/repo.git",
    "branch": "main",
    "commit": "abc123"
  },
  "scanners": ["semgrep", "gitleaks", "trivy"],
  "options": {
    "timeout": 3600,
    "parallel": true,
    "max_workers": 4,
    "severity_threshold": "HIGH",
    "risk_threshold": 70
  },
  "filters": {
    "include": ["*.py", "*.js"],
    "exclude": ["*.test.*", "node_modules/*"]
  },
  "notifications": {
    "enabled": true,
    "channels": ["slack", "email"],
    "severity_threshold": "CRITICAL"
  }
}
```

#### Estado del Scan
```http
GET /api/v1/scans/{scan_id}
Authorization: Bearer {token}

Response:
{
  "scan_id": "scan_20241221_143022",
  "status": "running",
  "progress": 65,
  "started_at": "2024-12-21T14:30:22Z",
  "estimated_completion": "2024-12-21T14:45:00Z",
  "current_scanner": "semgrep",
  "scanners_completed": 2,
  "total_scanners": 5,
  "findings_count": 15,
  "risk_score": 45.5,
  "risk_level": "MEDIUM"
}
```

#### Resultados del Scan
```http
GET /api/v1/scans/{scan_id}/results
Authorization: Bearer {token}

Response:
{
  "scan_id": "scan_20241221_143022",
  "status": "completed",
  "risk_score": 78.5,
  "risk_level": "HIGH",
  "total_findings": 23,
  "findings_by_severity": {
    "CRITICAL": 2,
    "HIGH": 8,
    "MEDIUM": 10,
    "LOW": 3
  },
  "findings_by_scanner": {
    "semgrep": 12,
    "gitleaks": 5,
    "trivy": 6
  },
  "scan_duration": 1245.67,
  "findings": [
    {
      "id": "finding_001",
      "scanner": "semgrep",
      "severity": "CRITICAL",
      "title": "SQL Injection Vulnerability",
      "description": "Potential SQL injection in user input",
      "file_path": "src/api/users.py",
      "line_number": 45,
      "column_number": 12,
      "code_snippet": "query = f\"SELECT * FROM users WHERE id = {user_id}\"",
      "risk_score": 95.0,
      "confidence": 0.95,
      "tags": ["security", "sql-injection", "owasp-top10"],
      "cwe_id": "CWE-89",
      "cve_id": "CVE-2024-1234",
      "cvss_score": 9.8,
      "remediation": {
        "description": "Use parameterized queries",
        "confidence": 0.9,
        "automation_suggested": true,
        "steps": [
          "Replace string formatting with parameterized queries",
          "Use ORM methods instead of raw SQL",
          "Validate and sanitize user input"
        ],
        "references": [
          "https://owasp.org/www-community/attacks/SQL_Injection",
          "https://docs.python.org/3/library/sqlite3.html"
        ]
      }
    }
  ],
  "metadata": {
    "repository": "https://github.com/user/repo.git",
    "branch": "main",
    "commit": "abc123",
    "scanned_files": 1250,
    "total_lines": 45000,
    "languages": ["python", "javascript", "typescript"]
  }
}
```

### Gestión de Reportes

#### Generar Reporte
```http
POST /api/v1/reports
Authorization: Bearer {token}
Content-Type: application/json

{
  "scan_id": "scan_20241221_143022",
  "format": "html",
  "template": "executive",
  "options": {
    "include_remediation": true,
    "include_code_snippets": true,
    "group_by_severity": true,
    "include_trends": true
  }
}
```

#### Descargar Reporte
```http
GET /api/v1/reports/{report_id}/download
Authorization: Bearer {token}

Response: Binary file (PDF, HTML, JSON, etc.)
```

### Gestión de Configuración

#### Obtener Configuración
```http
GET /api/v1/config
Authorization: Bearer {token}

Response:
{
  "scanners": {
    "semgrep": {
      "enabled": true,
      "timeout": 1800,
      "config_file": "semgrep-config.yaml",
      "rules": ["security", "python", "javascript"]
    },
    "gitleaks": {
      "enabled": true,
      "timeout": 600,
      "config_file": "gitleaks-config.toml",
      "scan_history": true
    }
  },
  "workspace": {
    "dir": "/var/lib/repo-scan",
    "max_size": "10G",
    "cleanup_after": "7d"
  },
  "notifications": {
    "slack": {
      "enabled": true,
      "webhook_url": "https://hooks.slack.com/...",
      "channel": "#security-alerts"
    }
  }
}
```

#### Actualizar Configuración
```http
PUT /api/v1/config
Authorization: Bearer {token}
Content-Type: application/json

{
  "scanners": {
    "semgrep": {
      "timeout": 2400
    }
  }
}
```

### WebSocket en Tiempo Real

#### Conexión WebSocket
```javascript
const ws = new WebSocket('wss://api.repo-scan.com/ws/scans/{scan_id}');

ws.onmessage = function(event) {
  const data = JSON.parse(event.data);
  
  switch(data.type) {
    case 'scan_progress':
      updateProgressBar(data.progress);
      break;
    case 'scanner_started':
      showScannerStatus(data.scanner, 'running');
      break;
    case 'scanner_completed':
      showScannerStatus(data.scanner, 'completed');
      break;
    case 'finding_detected':
      addFindingToList(data.finding);
      break;
    case 'scan_completed':
      showScanResults(data.results);
      break;
  }
};
```

### Gestión de Plugins

#### Listar Plugins
```http
GET /api/v1/plugins
Authorization: Bearer {token}

Response:
{
  "plugins": [
    {
      "name": "custom-scanner",
      "version": "1.0.0",
      "description": "Custom security scanner",
      "enabled": true,
      "config": {
        "api_key": "***",
        "endpoint": "https://api.custom-scanner.com"
      }
    }
  ]
}
```

#### Instalar Plugin
```http
POST /api/v1/plugins
Authorization: Bearer {token}
Content-Type: application/json

{
  "name": "custom-scanner",
  "source": "https://github.com/user/custom-scanner",
  "version": "1.0.0"
}
```

### Estadísticas y Métricas

#### Dashboard de Estadísticas
```http
GET /api/v1/stats/dashboard
Authorization: Bearer {token}

Response:
{
  "total_scans": 1250,
  "scans_today": 15,
  "total_findings": 5670,
  "critical_findings": 45,
  "avg_risk_score": 65.5,
  "scans_by_status": {
    "completed": 1200,
    "running": 5,
    "failed": 45
  },
  "findings_by_severity": {
    "CRITICAL": 45,
    "HIGH": 234,
    "MEDIUM": 1234,
    "LOW": 4157
  },
  "top_vulnerabilities": [
    {
      "title": "SQL Injection",
      "count": 23,
      "severity": "CRITICAL"
    }
  ],
  "scan_trends": {
    "last_7_days": [12, 15, 8, 20, 18, 14, 16],
    "last_30_days": [450, 467, 423, 489, 512, 498, 456]
  }
}
```

### Integración con SIEM

#### Envío a SIEM
```http
POST /api/v1/integrations/siem
Authorization: Bearer {token}
Content-Type: application/json

{
  "siem_type": "splunk",
  "endpoint": "https://splunk.company.com:8089",
  "token": "splunk-token",
  "scan_id": "scan_20241221_143022",
  "format": "cef"
}
```

## 🔐 Autenticación y Autorización

### OIDC Integration
```http
GET /api/v1/auth/oidc/login
# Redirects to OIDC provider

GET /api/v1/auth/oidc/callback?code=...
# Handles OIDC callback
```

### API Keys
```http
POST /api/v1/auth/api-keys
Authorization: Bearer {token}
Content-Type: application/json

{
  "name": "CI/CD Integration",
  "expires_in": 86400,
  "permissions": ["scan:read", "scan:create"]
}

Response:
{
  "api_key": "rs_sk_1234567890abcdef...",
  "expires_at": "2024-12-22T14:30:22Z"
}
```

## 📊 Rate Limiting

```http
X-RateLimit-Limit: 1000
X-RateLimit-Remaining: 999
X-RateLimit-Reset: 1640995200
```

## 🎯 Códigos de Estado HTTP

- `200 OK` - Operación exitosa
- `201 Created` - Recurso creado
- `400 Bad Request` - Solicitud inválida
- `401 Unauthorized` - No autenticado
- `403 Forbidden` - Sin permisos
- `404 Not Found` - Recurso no encontrado
- `429 Too Many Requests` - Rate limit excedido
- `500 Internal Server Error` - Error del servidor
