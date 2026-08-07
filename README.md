# Plataforma de verificacion de configuraciones Windows

Prototipo funcional para detectar configuraciones inseguras en equipos Windows autorizados y verificar automaticamente su correccion con evidencia antes/despues.

## Componentes

- API FastAPI con autenticacion por token de agente.
- Base de datos SQLite local en `data/cybercheck.db`.
- Motor de reglas para cortafuegos, RDP, servicios, administradores, actualizaciones, antivirus y respaldos.
- Panel web para equipos, hallazgos, evidencias, tareas de verificacion y reportes.
- Agente Python para Windows con tareas cerradas: `FULL_SCAN`, `VERIFY_FIREWALL`, `VERIFY_PORTS`, `VERIFY_SERVICES`, `VERIFY_ADMINISTRATORS`, `VERIFY_UPDATES`, `VERIFY_ANTIVIRUS`, `VERIFY_DEVICES`, `VERIFY_BACKUP`.
- Base V2.1 incremental: modulos de agente, inventario avanzado, controles de seguridad, software instalado, procesos con metadata segura, eventos de seguridad permitidos, snapshots y cambios historicos.

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

## Despliegue en Render

1. Crea una base PostgreSQL en Render.
2. Crea un Web Service conectado al repositorio de GitHub.
3. Usa estos comandos:

```text
Build command: pip install -r requirements.txt
Start command: uvicorn app.main:app --host 0.0.0.0 --port $PORT
```

4. En Environment agrega `DATABASE_URL` con la Internal Database URL de Render.
5. Agrega tambien credenciales del panel:

```text
ADMIN_USERNAME=admin
ADMIN_PASSWORD=elige-una-contrasena-segura
SESSION_SECRET=un-texto-largo-aleatorio
AGENT_REGISTRATION_CODE=codigo-largo-para-registrar-agentes
```

Si `DATABASE_URL` existe, la app usa PostgreSQL. Si no existe, usa SQLite local en `data/cybercheck.db`.

En desarrollo local, si no configuras esas variables, el login usa `admin` / `admin123`.

Al iniciar no se crean equipos demo. El dashboard mostrara `No hay agentes registrados` hasta que un agente real se registre.

## Ejecutar el agente

Edita `agent/agent_config.example.json` si necesitas cambiar la URL o ruta de respaldos. Luego ejecuta:

```powershell
py -3.12 agent/windows_agent.py --config agent/agent_config.example.json --scan FULL_SCAN
```

Para consultar tareas pendientes y ejecutar verificaciones solicitadas desde el panel:

```powershell
py -3.12 agent/windows_agent.py --config agent/agent_config.example.json --poll-once
```

Para dejar el agente escuchando tareas mientras pruebas el panel:

```powershell
py -3.12 agent/windows_agent.py --config agent/agent_config.render.example.json --loop --interval 60 --max-tasks 10
```

Para enviar evidencia real a la plataforma desplegada en Render:

```powershell
copy agent\agent_config.render.example.json agent\agent_config.render.json
# Edita registration_code con el mismo AGENT_REGISTRATION_CODE configurado en Render.
py -3.12 agent/windows_agent.py --config agent/agent_config.render.json --register
py -3.12 agent/windows_agent.py --config agent/agent_config.render.json --scan FULL_SCAN
```

Para instalar una tarea programada que consulte verificaciones pendientes cada 15 minutos:

```powershell
powershell -ExecutionPolicy Bypass -File agent/install_scheduled_task.ps1
```

Si Windows niega permisos porque ya existe una tarea elevada, instala una tarea de usuario con otro nombre:

```powershell
powershell -ExecutionPolicy Bypass -File agent/install_scheduled_task.ps1 -TaskName "CyberCheck MIPYME Agent User"
```

Para instalarla con privilegios elevados, abre PowerShell como administrador y agrega `-RunElevated`.

## Pruebas

```powershell
py -3.12 -m unittest discover -s tests
```

## Alcance de seguridad

El agente no ejecuta comandos libres enviados por la API. Solo corre funciones locales predefinidas, no lee documentos personales, no captura credenciales, no toma capturas de pantalla, no registra teclas, no lee correos y no inspecciona comunicaciones.

Los modulos V2.1 recopilan solo telemetria tecnica autorizada del endpoint:

- inventario de sistema;
- TPM, Secure Boot, BitLocker, UAC, SMBv1 y RDP;
- software instalado;
- procesos activos con nombre, ruta, firma y metadata tecnica, sin argumentos de linea de comandos;
- eventos permitidos del registro de seguridad de Windows;
- snapshots y cambios entre snapshots.
