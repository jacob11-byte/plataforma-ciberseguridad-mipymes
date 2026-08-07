# Plataforma de verificacion de configuraciones Windows

Prototipo funcional para detectar configuraciones inseguras en equipos Windows autorizados y verificar automaticamente su correccion con evidencia antes/despues.

## Componentes

- API FastAPI con autenticacion por token de agente.
- Base de datos SQLite local en `data/cybercheck.db`.
- Motor de reglas para cortafuegos, RDP, servicios, administradores, actualizaciones, antivirus y respaldos.
- Panel web para equipos, hallazgos, evidencias, tareas de verificacion y reportes.
- Agente Python para Windows con tareas cerradas: `FULL_SCAN`, `VERIFY_FIREWALL`, `VERIFY_PORTS`, `VERIFY_SERVICES`, `VERIFY_ADMINISTRATORS`, `VERIFY_UPDATES`, `VERIFY_ANTIVIRUS`, `VERIFY_BACKUP`.

## Instalacion

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

## Ejecutar la plataforma

```powershell
py -3.12 -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Abre el panel en:

```text
http://127.0.0.1:8000
```

Al iniciar se crea un equipo demo:

- `device_id`: `PC-CONTABILIDAD-001`
- `token`: `demo-token`

## Ejecutar el agente

Edita `agent/agent_config.example.json` si necesitas cambiar la URL o ruta de respaldos. Luego ejecuta:

```powershell
py -3.12 agent/windows_agent.py --config agent/agent_config.example.json --scan FULL_SCAN
```

Para consultar tareas pendientes y ejecutar verificaciones solicitadas desde el panel:

```powershell
py -3.12 agent/windows_agent.py --config agent/agent_config.example.json --poll-once
```

## Pruebas

```powershell
py -3.12 -m unittest discover -s tests
```

## Alcance de seguridad

El agente no ejecuta comandos libres enviados por la API. Solo corre funciones locales predefinidas, no lee documentos personales, no captura credenciales, no toma capturas de pantalla y no inspecciona comunicaciones.
