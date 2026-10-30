# Plataforma de verificacion de configuraciones Windows

Prototipo funcional para detectar configuraciones inseguras en equipos Windows autorizados y verificar automaticamente su correccion con evidencia antes/despues.

## Componentes

- API FastAPI con autenticacion por token de agente.
- Base de datos SQLite local en `data/cybercheck.db`.
- Motor de reglas para cortafuegos, RDP, servicios, administradores, actualizaciones, antivirus y respaldos.
- Panel web para equipos, hallazgos, evidencias y tareas de verificacion.
- Agente Python para Windows con tareas cerradas: `FULL_SCAN`, `VERIFY_FIREWALL`, `VERIFY_PORTS`, `VERIFY_SERVICES`, `VERIFY_ADMINISTRATORS`, `VERIFY_UPDATES`, `VERIFY_ANTIVIRUS`, `VERIFY_DEVICES`, `VERIFY_BACKUP`.
- Base V2.1 incremental: modulos de agente, inventario avanzado, controles de seguridad, software instalado, procesos con metadata segura, eventos de seguridad permitidos, snapshots y cambios historicos.

## Estado del producto

La version actual es un piloto `0.5` de una sola organizacion. El agente usa una
lista cerrada de verificaciones; ninguna IA ejecuta comandos en los equipos.
Incluye un servicio de Windows independiente de la sesion, cola SQLite para
resultados sin conexion, aplicacion de bandeja con estado sanitizado, bloqueo
contra procesos solapados, tareas con lease e identificador idempotente, y
estados parciales cuando una consulta no produjo evidencia suficiente.

### Vulnerabilidades (CVE)

Cada equipo muestra una pestana **Vulnerabilidades** con tres fuentes:

- **Parches de Windows pendientes**: el agente lee de Windows Update que KB
  faltan; el servidor los traduce a CVE con el boletin oficial de Microsoft
  (MSRC, ultimos 3 meses) porque Windows Update casi nunca informa los CVE de
  las actualizaciones acumulativas.
- **Programas instalados con fallas conocidas** y **programas sin soporte**
  (Flash, Silverlight, QuickTime, Python 2), segun una base curada en
  `app/vulndb.py` con la version que corrige cada CVE. Es deliberadamente
  corta: solo incluye entradas verificables. Se amplia con un JSON propio
  (`VULN_DB_PATH`, ver el formato en `vulndb.entries()`).
- **Explotacion real**: se marca como "explotada activamente" toda CVE que
  figure en el catalogo CISA KEV o que Microsoft marque `Exploited:Yes`; esos
  casos generan hallazgos **criticos**.

Los catalogos se descargan en segundo plano al arrancar y se renuevan cada 24 h;
mientras no esten cargados el panel lo indica y no afirma que algo "no esta
explotado". El boletin de Microsoft pesa ~20 MB por mes: el servidor llega a
~260 MB de pico al procesarlo (usa `MSRC_MONTHS=1` o `MSRC_DISABLED=true` en
instancias de 512 MB muy justas). Esto detecta vulnerabilidades **conocidas y
catalogadas**; no es un escaner de vulnerabilidades completo (no prueba
servicios ni configuraciones de aplicaciones de terceros fuera de la base).

### Monitoreo en tiempo real

El servicio del agente consulta cada 30 s los eventos nuevos y envia al panel,
en segundos, lo que importa para la seguridad (pestana **En vivo**, tambien por
equipo): rafagas de inicios de sesion fallidos (fuerza bruta), cuentas creadas,
cuentas agregadas a Administradores, borrado del registro de seguridad,
servicios instalados, detecciones y apagado de Defender, procesos nuevos sin
firma en carpetas de usuario, puertos nuevos abiertos a la red y USB. Los
eventos graves tambien llegan por correo (maximo uno cada 10 minutos por
equipo). Tambien aplica `"realtime": false` en la configuracion para apagarlo.

No recolecta titulos de ventanas, tiempo por aplicacion, archivos ni teclas:
es telemetria de seguridad, no vigilancia de productividad. Los eventos de
seguridad del registro de Windows requieren ejecutar el agente como servicio
(SYSTEM). Si el equipo esta sin Internet los eventos esperan en memoria (hasta
500) y se envian al volver la conexion; no sobreviven a un reinicio.

### Alertas por correo e informes

Con un servidor SMTP configurado, cada vez que un equipo muestra un problema
**nuevo** (o reabierto) de gravedad Critica o Alta, los administradores y
tecnicos de esa cuenta cuyo usuario es un correo reciben un mensaje con el
detalle y el enlace al diagnostico. Un correo por revision, no por problema.

```text
SMTP_HOST=smtp.tu-proveedor.com
SMTP_PORT=587            # 465 usa SSL directo
SMTP_USER=...
SMTP_PASSWORD=...
SMTP_FROM=alertas@tu-dominio.com
```

El mismo SMTP habilita la **recuperacion de contrasena** (enlace de un solo uso
valido 1 hora; cambiar la contrasena cierra las sesiones abiertas) y un aviso
cuando un equipo **deja de reportar** durante `OFFLINE_ALERT_HOURS` horas
(48 por defecto), una vez por caida; un agente desactivado por un atacante
se nota asi. `PUBLIC_BASE_URL` define el dominio usado en los enlaces.

Sin `SMTP_HOST` las alertas quedan desactivadas. En el detalle de cada equipo,
**Informe PDF** abre un informe listo para entregar al cliente (puntaje,
datos del equipo, cada problema con su diagnostico y los controles no
verificados); desde el navegador se guarda como PDF.

### Diagnostico de cada problema

Cada hallazgo explica, con los datos reales del equipo:

- **Que se encontro**: la cuenta, IP, KB, puerto y proceso, ruta, exclusion o
  carpeta compartida exacta (por ejemplo "14 inicios fallidos contra
  'contabilidad' desde 185.220.101.4 por escritorio remoto, contrasena incorrecta").
- **Por que es peligroso**: como lo aprovecharia un atacante.
- **Como corregirlo**: pasos concretos y el comando de PowerShell para copiar.
- **Referencias**: tecnica de MITRE ATT&CK y CIS Controls v8.

Cada equipo recibe un puntaje de 0 a 100 (nota A-F) segun sus problemas
abiertos, y el panel indica que controles no se pudieron verificar y por que.

El agente revisa, ademas de firewall, antivirus, parches, puertos, servicios y
respaldos: cuentas Invitado/Administrador y sin contrasena, politica de
contrasenas y bloqueo, WDigest, NTLMv1, LLMNR, exclusiones de Defender,
programas de inicio sin firma, carpetas compartidas con "Todos", procesos sin
firma en carpetas de usuario, BitLocker, Secure Boot, fin de soporte de Windows
y eventos de ataque de las ultimas 24 h (fuerza bruta, cuentas creadas,
cambios en Administradores, borrado del registro, servicios sospechosos).

El servicio ejecuta una revision completa al instalarse y luego cada 12 horas
(`auto_scan_hours` en la configuracion; 0 la desactiva), sin que nadie la pida.

El panel tiene usuarios con roles, auditoria de acciones y rotacion de
credenciales de agentes:

| Rol | Puede |
| --- | --- |
| `viewer` (Solo lectura) | Ver equipos, hallazgos, evidencia y usar el analista |
| `technician` (Tecnico) | Lo anterior y solicitar revisiones |
| `admin` (Administrador) | Lo anterior, desconectar/reactivar equipos, rotar credenciales, gestionar usuarios y ver la auditoria |

El usuario de `ADMIN_USERNAME`/`ADMIN_PASSWORD` es el administrador inicial y
no se guarda en la base de datos; desde la pestana **Usuarios** se crean las
demas cuentas (contrasenas de 12+ caracteres, almacenadas con scrypt). Cambiar
contrasena, rol o desactivar un usuario cierra sus sesiones abiertas.

Cada credencial de agente se renueva automaticamente al superar
`AGENT_CREDENTIAL_MAX_AGE_DAYS` (90 por defecto) o cuando un administrador pulsa
**Rotar credencial**. El token anterior sigue valido hasta que el agente usa el
nuevo (maximo 24 horas), de modo que un corte de red durante la rotacion no
deja al equipo sin acceso. Si un equipo es desconectado desde el panel, la
bandeja lo muestra como "Equipo desconectado desde el panel".

La integracion Wazuh incluida es todavia un cliente de lectura y laboratorio;
no se activa solamente definiendo variables de entorno. El aislamiento entre
varias empresas, instalador autocontenido firmado y sincronizacion Wazuh de
extremo a extremo son trabajo posterior al piloto.

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
CYBERCHECK_ENV=production
# Opcional: dias de vida de cada credencial de agente (por defecto 90)
AGENT_CREDENTIAL_MAX_AGE_DAYS=90
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

La tarea programada se conserva solo como modo de desarrollo o compatibilidad:

```powershell
powershell -ExecutionPolicy Bypass -File agent/install_scheduled_task.ps1
```

El instalador usa `pythonw.exe`, oculta la tarea y evita instancias paralelas.
No combines este modo con el servicio empresarial.

### Cuentas y agregar computadoras desde el panel (recomendado)

Cualquier persona crea su cuenta en `/login` (pestana **Crear cuenta**, con
correo y contrasena, o **Continuar con Google**). Cada cuenta es una empresa
aislada: sus usuarios solo ven sus propias computadoras, hallazgos y auditoria.

Para proteger una computadora, en el panel se pulsa **+ Agregar computadora**.
Se descarga `CyberCheckSetup_<token>.exe`, donde `<token>` es un codigo de
inscripcion de 30 dias atado a esa empresa. Al abrirlo en el equipo (doble
clic, aceptar el permiso de administrador) el agente se instala, se registra en
esa cuenta y el panel avisa "Computadora conectada". Los administradores pueden
invalidar todos los instaladores descargados con `POST /api/agent/installer/revoke`.

El servidor sirve el instalador generico publicado en GitHub Releases
(`AGENT_INSTALLER_URL`, por defecto la ultima release de este repositorio) y lo
guarda en cache una hora. Opcionalmente `AGENT_INSTALLER_SHA256` verifica su hash.

Variables para el inicio con Google (opcional; sin ellas el boton no aparece):

```text
GOOGLE_CLIENT_ID=...apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=...
PUBLIC_BASE_URL=https://plataforma-ciberseguridad-mipymes.onrender.com
```

En Google Cloud Console > APIs y servicios > Credenciales, crea un "ID de
cliente de OAuth" de tipo Aplicacion web con la URI de redireccion
`https://<tu-dominio>/auth/google/callback`. `SIGNUP_ENABLED=false` desactiva
la creacion de cuentas nuevas.

El administrador de `ADMIN_USERNAME` y los agentes registrados con
`AGENT_REGISTRATION_CODE` pertenecen a la empresa `DEFAULT_COMPANY_NAME`
(por defecto `MIPYME Principal`).

### Compilar y publicar el instalador generico

`CyberCheckSetup.exe` instala el agente en cualquier PC o VM Windows sin
escribir comandos. El generico no lleva credenciales: la cuenta la aporta el
token del nombre del archivo descargado desde el panel.

1. Copia `agent/enrollment.example.json` a `agent/enrollment.json` (solo
   `api_url` y valores por defecto; nunca `device_id`, `token` ni, para la
   version publica, `registration_code`).
2. Compila:

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements-agent-build.txt
powershell -ExecutionPolicy Bypass -File agent/build_standalone.ps1 -PythonExe .venv\Scripts\python.exe
```

El resultado es `dist\CyberCheckSetup.exe`. Publicalo como asset de una release
para que el panel lo entregue:

```powershell
gh release create agent-v0.6.0 dist\CyberCheckSetup.exe --title "Agente 0.6.0" --notes "Instalador generico"
```

Al ejecutarlo:

- detiene y reemplaza versiones anteriores y elimina tareas programadas heredadas;
- repara permisos de instalaciones previas en `ProgramData\CyberCheck`;
- conserva la identidad del equipo al actualizar, y lo vuelve a registrar si
  el panel ya no reconoce su credencial (por ejemplo, tras cambiar de base de datos);
- registra el servicio, el icono de bandeja y la entrada en
  **Configuracion > Aplicaciones** para desinstalarlo.

Despliegue masivo (GPO, Intune, RMM) sin ventanas:

```text
CyberCheckSetup.exe /quiet
CyberCheckSetup.exe /uninstall /quiet          conserva configuracion y cola
CyberCheckSetup.exe /uninstall /purge /quiet   elimina tambien los datos
```

El registro de la instalacion queda en `C:\ProgramData\CyberCheck\setup.log`.
El ejecutable aun no esta firmado: Windows SmartScreen puede mostrar
"Editor desconocido" hasta que se firme con un certificado de firma de codigo.

### Instalacion con scripts de PowerShell (alternativa)

Desde PowerShell como administrador, tras compilar:

```powershell
powershell -ExecutionPolicy Bypass -File agent/install_enterprise_agent.ps1
```

Esto instala `CyberCheckAgent` como servicio de inicio automatico diferido bajo
`SYSTEM`, registra el icono de bandeja para los inicios de sesion y elimina las
tareas programadas heredadas. La configuracion, el token, la cola offline y los
logs se guardan en `ProgramData` con acceso de Administradores/SYSTEM. La
bandeja solo puede leer `ProgramData\CyberCheck\public\status.json` y nunca
recibe credenciales.

Para desinstalar conservando configuracion, cola y logs:

```powershell
powershell -ExecutionPolicy Bypass -File agent/uninstall_enterprise_agent.ps1
```

Agrega `-RemoveData` unicamente si tambien deseas eliminar configuracion, cola,
token y logs.

La API publica dos comprobaciones operativas:

```text
GET /health/live   proceso disponible
GET /health/ready  base de datos disponible
```

## Pruebas

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
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
