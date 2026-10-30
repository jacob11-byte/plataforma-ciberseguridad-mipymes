from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from typing import Any

from . import plain, vulndb


@dataclass(frozen=True)
class RuleResult:
    rule_id: str
    control: str
    title: str
    severity: str
    triggered: bool
    evidence: dict[str, Any]
    recommendation: str
    closure_criteria: str
    # Diagnosis: what exactly was found on this device, why it matters, and
    # how to fix it. Filled from the measured evidence and KNOWLEDGE below.
    detail: str = ""
    risk: str = ""
    steps: tuple[str, ...] = field(default_factory=tuple)
    fix_command: str | None = None
    references: tuple[str, ...] = field(default_factory=tuple)

    def diagnosis(self) -> dict[str, Any]:
        return {
            "plain": plain.explain(self.rule_id, self.severity, self.evidence),
            "detail": self.detail,
            "risk": self.risk,
            "steps": list(self.steps),
            "fix_command": self.fix_command,
            "references": list(self.references),
        }


# Why each condition is dangerous and how to correct it. References use
# MITRE ATT&CK technique IDs and CIS Critical Security Controls v8.
KNOWLEDGE: dict[str, dict[str, Any]] = {
    "FIREWALL_PUBLIC_DISABLED": {
        "risk": "Sin firewall en redes publicas (cafeterias, hoteles, aeropuertos) cualquier equipo de la misma red puede alcanzar los servicios del equipo: carpetas compartidas, escritorio remoto o programas con puertos abiertos. Es una de las vias mas usadas para propagar ransomware.",
        "steps": [
            "Abre Seguridad de Windows > Firewall y proteccion de red.",
            "Selecciona 'Red publica' y activa Firewall de Microsoft Defender.",
            "Repite para 'Red de dominio' y 'Red privada' si tambien estan apagadas.",
        ],
        "fix": "Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True",
        "refs": ["CIS Control 4.4 - Firewall en equipos", "MITRE ATT&CK T1562.004 - Desactivar firewall"],
    },
    "RDP_EXPOSED": {
        "risk": "El Escritorio remoto (RDP) es la puerta de entrada numero uno del ransomware en pequenas empresas: los atacantes prueban contrasenas de forma automatizada o explotan fallas como BlueKeep. Si el puerto 3389 es alcanzable, el equipo puede ser controlado completamente.",
        "steps": [
            "Si nadie se conecta remotamente a este equipo: Configuracion > Sistema > Escritorio remoto > Desactivado.",
            "Si se necesita: exige NLA, usa contrasenas largas, limita el acceso a una VPN y nunca publiques el puerto 3389 en el router.",
            "Revisa en el registro de seguridad si hubo intentos de inicio de sesion fallidos (evento 4625).",
        ],
        "fix": "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' -Name fDenyTSConnections -Value 1; Stop-Service TermService -Force",
        "refs": ["MITRE ATT&CK T1021.001 - Remote Desktop Protocol", "MITRE ATT&CK T1110 - Fuerza bruta", "CIS Control 4.8 - Desactivar servicios innecesarios"],
    },
    "RISKY_SERVICE_ENABLED": {
        "risk": "Registro remoto y WinRM permiten leer o cambiar la configuracion del equipo desde la red. Un atacante con una credencial robada los usa para moverse lateralmente entre equipos sin instalar nada.",
        "steps": [
            "Confirma con el area de TI si el servicio se usa para administracion.",
            "Si no se usa, detenlo y cambia su inicio a Deshabilitado en services.msc.",
        ],
        "fix": "Stop-Service RemoteRegistry -Force; Set-Service RemoteRegistry -StartupType Disabled",
        "refs": ["MITRE ATT&CK T1021.006 - Windows Remote Management", "MITRE ATT&CK T1112 - Modificar registro", "CIS Control 4.8"],
    },
    "UNAUTHORIZED_LOCAL_ADMIN": {
        "risk": "Cada administrador adicional es una cuenta que, si se roba su contrasena, da control total del equipo: desactivar el antivirus, instalar malware y robar credenciales de otros usuarios.",
        "steps": [
            "Abre Administracion de equipos > Usuarios y grupos locales > Grupos > Administradores.",
            "Retira las cuentas que no esten en la lista autorizada; dales una cuenta estandar para el dia a dia.",
        ],
        "fix": "Remove-LocalGroupMember -SID S-1-5-32-544 -Member '<cuenta>'",
        "refs": ["CIS Control 5.4 - Restringir privilegios de administrador", "MITRE ATT&CK T1078.003 - Cuentas locales"],
    },
    "UPDATES_PENDING": {
        "risk": "Las actualizaciones corrigen vulnerabilidades que ya son publicas. Despues de cada 'Patch Tuesday' los atacantes analizan los parches y en dias crean exploits para equipos que no se actualizaron.",
        "steps": [
            "Abre Configuracion > Windows Update y pulsa Buscar actualizaciones.",
            "Instala todas, priorizando las de seguridad marcadas como criticas.",
            "Reinicia el equipo si Windows lo solicita: sin reiniciar el parche no queda aplicado.",
        ],
        "fix": "UsoClient StartInteractiveScan",
        "refs": ["CIS Control 7.3 - Parches automaticos del sistema operativo", "MITRE ATT&CK T1190 - Explotar aplicacion expuesta"],
    },
    "ANTIVIRUS_DISABLED": {
        "risk": "Sin proteccion en tiempo real un archivo malicioso se ejecuta sin que nada lo detenga. Desactivar Defender es tambien el primer paso de casi todos los ataques de ransomware.",
        "steps": [
            "Abre Seguridad de Windows > Proteccion contra virus y amenazas > Administrar configuracion.",
            "Activa Proteccion en tiempo real, Proteccion basada en la nube y Proteccion contra alteraciones.",
            "Si hay una politica que lo desactiva (valores Disable* en Get-MpPreference), averigua quien la configuro.",
        ],
        "fix": "Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false",
        "refs": ["CIS Control 10.1 - Antimalware", "MITRE ATT&CK T1562.001 - Desactivar herramientas de seguridad"],
    },
    "ANTIVIRUS_SIGNATURES_OLD": {
        "risk": "Con firmas viejas el antivirus no reconoce el malware aparecido en los ultimos dias, que es justamente el que circula en campanas activas.",
        "steps": [
            "Abre Seguridad de Windows > Proteccion contra virus y amenazas > Buscar actualizaciones.",
            "Si falla, revisa que Windows Update funcione y que el equipo tenga Internet.",
        ],
        "fix": "Update-MpSignature",
        "refs": ["CIS Control 10.2 - Actualizacion automatica de firmas"],
    },
    "ANTIVIRUS_SCAN_OLD": {
        "risk": "Un archivo que entro antes de que existiera su firma solo se detecta en un escaneo posterior. Sin escaneos periodicos puede quedar oculto indefinidamente.",
        "steps": ["Ejecuta un analisis rapido desde Seguridad de Windows.", "Programa un analisis semanal."],
        "fix": "Start-MpScan -ScanType QuickScan",
        "refs": ["CIS Control 10.1"],
    },
    "ANTIVIRUS_ACTIVE_THREATS": {
        "risk": "El antivirus encontro software malicioso que sigue presente o activo. Puede estar robando contrasenas, cifrando archivos o dando acceso remoto a un atacante en este momento.",
        "steps": [
            "Desconecta el equipo de la red si la amenaza es grave o se ejecuto.",
            "Abre Seguridad de Windows > Historial de proteccion y aplica 'Quitar' o 'Poner en cuarentena'.",
            "Ejecuta un analisis completo y luego el analisis sin conexion de Microsoft Defender.",
            "Cambia las contrasenas usadas en este equipo desde otro equipo limpio.",
        ],
        "fix": "Remove-MpThreat; Start-MpScan -ScanType FullScan",
        "refs": ["CIS Control 10.1", "CIS Control 17 - Respuesta a incidentes"],
    },
    "USB_STORAGE_CONNECTED": {
        "risk": "Las memorias USB introducen malware y permiten sacar informacion de la empresa sin dejar rastro en la red.",
        "steps": ["Confirma que el dispositivo sea de la empresa.", "Escanealo con el antivirus antes de abrir archivos."],
        "fix": None,
        "refs": ["CIS Control 10.3 - Desactivar autoejecucion de medios extraibles", "MITRE ATT&CK T1091 - Medios extraibles"],
    },
    "UNSIGNED_DEVICE_DRIVER": {
        "risk": "Un controlador se ejecuta con el maximo privilegio del sistema (kernel). Los controladores sin firma pueden ser maliciosos o vulnerables y se usan para apagar antivirus.",
        "steps": ["Identifica el fabricante del controlador.", "Reemplazalo por la version firmada desde el sitio oficial o retira el dispositivo."],
        "fix": "pnputil /enum-drivers",
        "refs": ["MITRE ATT&CK T1068 - Escalamiento de privilegios", "MITRE ATT&CK T1014 - Rootkit"],
    },
    "DEVICE_WITH_ERROR": {
        "risk": "Un dispositivo con error puede indicar un controlador danado o manipulado; tambien afecta la estabilidad del equipo.",
        "steps": ["Abre el Administrador de dispositivos.", "Actualiza o reinstala el controlador del dispositivo marcado con error."],
        "fix": "Get-PnpDevice -Status ERROR",
        "refs": [],
    },
    "BACKUP_OLD_OR_MISSING": {
        "risk": "Ante ransomware, un disco danado o un robo, el respaldo es lo unico que permite recuperar la informacion. Sin respaldo reciente la empresa pierde los datos de esos dias o paga el rescate.",
        "steps": [
            "Ejecuta un respaldo ahora y confirma que el archivo se creo con un tamano razonable.",
            "Programa respaldos automaticos diarios y guarda una copia fuera del equipo (nube o disco desconectado).",
            "Prueba restaurar un archivo al menos una vez al mes.",
        ],
        "fix": None,
        "refs": ["CIS Control 11 - Recuperacion de datos", "MITRE ATT&CK T1486 - Cifrado de datos (ransomware)"],
    },
    "UAC_DISABLED": {
        "risk": "Con UAC desactivado todo programa que abre el usuario corre como administrador: un adjunto malicioso obtiene control total sin ninguna advertencia.",
        "steps": ["Abre 'Cambiar configuracion de Control de cuentas de usuario' y sube el nivel al recomendado.", "Reinicia el equipo."],
        "fix": "Set-ItemProperty 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' -Name EnableLUA -Value 1",
        "refs": ["MITRE ATT&CK T1548.002 - Evadir UAC", "CIS Benchmark Windows 2.3.17"],
    },
    "SMB1_ENABLED": {
        "risk": "SMBv1 es el protocolo que explotaron WannaCry y NotPetya (EternalBlue). Microsoft lo considera obsoleto y lo retira de Windows por inseguro.",
        "steps": ["Desactiva la caracteristica 'Compatibilidad con el protocolo para compartir archivos SMB 1.0/CIFS'.", "Reinicia el equipo."],
        "fix": "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart",
        "refs": ["MITRE ATT&CK T1210 - Explotar servicios remotos", "CIS Benchmark Windows 18.4.x"],
    },
    "RDP_NLA_DISABLED": {
        "risk": "Sin NLA la pantalla de inicio de sesion de RDP se entrega antes de autenticar: facilita la fuerza bruta y expone el equipo a vulnerabilidades previas al login.",
        "steps": ["Sistema > Escritorio remoto > Configuracion avanzada > 'Requerir autenticacion a nivel de red'."],
        "fix": "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' -Name UserAuthentication -Value 1",
        "refs": ["MITRE ATT&CK T1021.001", "CIS Benchmark Windows 18.10.57.3.9"],
    },
    "BITLOCKER_OFF": {
        "risk": "Si roban o se pierde el equipo, cualquiera puede sacar el disco y leer todos los archivos, correos y contrasenas guardadas. El cifrado lo impide.",
        "steps": [
            "Abre Panel de control > Cifrado de unidad BitLocker y activa BitLocker en la unidad del sistema.",
            "Guarda la clave de recuperacion en un lugar seguro fuera del equipo.",
        ],
        "fix": "Enable-BitLocker -MountPoint 'C:' -EncryptionMethod XtsAes256 -TpmProtector",
        "refs": ["CIS Control 3.6 - Cifrar datos en equipos", "MITRE ATT&CK T1005 - Datos del sistema local"],
    },
    "SECURE_BOOT_OFF": {
        "risk": "Secure Boot impide que se cargue codigo malicioso antes que Windows (bootkits). Sin el, un malware puede esconderse por debajo del antivirus.",
        "steps": ["Entra a la configuracion UEFI/BIOS del equipo y activa Secure Boot.", "Verifica despues con msinfo32: 'Estado de arranque seguro: Activado'."],
        "fix": "Confirm-SecureBootUEFI",
        "refs": ["MITRE ATT&CK T1542.003 - Bootkit", "CIS Control 4.1"],
    },
    "GUEST_ACCOUNT_ENABLED": {
        "risk": "La cuenta Invitado permite entrar al equipo sin credenciales propias y sin dejar rastro de quien fue.",
        "steps": ["Desactiva la cuenta Invitado en Administracion de equipos > Usuarios."],
        "fix": "Get-LocalUser | Where-Object { $_.SID -like '*-501' } | Disable-LocalUser",
        "refs": ["CIS Control 5.3 - Desactivar cuentas inactivas", "MITRE ATT&CK T1078.001 - Cuentas por defecto"],
    },
    "BUILTIN_ADMIN_ENABLED": {
        "risk": "La cuenta 'Administrador' integrada tiene un nombre conocido y no se bloquea por intentos fallidos: es el blanco favorito de la fuerza bruta.",
        "steps": ["Usa cuentas de administrador nominales y desactiva la integrada."],
        "fix": "Get-LocalUser | Where-Object { $_.SID -like '*-500' } | Disable-LocalUser",
        "refs": ["CIS Benchmark Windows 2.3.1.1", "MITRE ATT&CK T1078.001"],
    },
    "ACCOUNT_NO_PASSWORD_REQUIRED": {
        "risk": "Una cuenta que no requiere contrasena puede quedar con contrasena vacia: cualquiera entra al equipo o por la red con solo saber el nombre.",
        "steps": ["Asigna una contrasena a la cuenta y exige que la tenga."],
        "fix": "Set-LocalUser -Name '<cuenta>' -PasswordNeverExpires $false; net user <cuenta> /passwordreq:yes",
        "refs": ["CIS Control 5.2 - Contrasenas unicas", "MITRE ATT&CK T1078.003"],
    },
    "PASSWORD_POLICY_WEAK": {
        "risk": "Contrasenas cortas se adivinan en minutos y, sin bloqueo por intentos fallidos, un atacante puede probar millones de combinaciones sin ser detenido.",
        "steps": [
            "Abre secpol.msc > Directivas de cuenta.",
            "Longitud minima: 12 o mas. Umbral de bloqueo de cuenta: 5 a 10 intentos.",
        ],
        "fix": "net accounts /minpwlen:12 /lockoutthreshold:10 /lockoutduration:15",
        "refs": ["CIS Control 5.2", "CIS Benchmark Windows 1.1.4 y 1.2.2", "MITRE ATT&CK T1110"],
    },
    "WDIGEST_PLAINTEXT": {
        "risk": "Con WDigest activo Windows guarda en memoria las contrasenas en texto plano. Herramientas como Mimikatz las extraen en segundos y el atacante obtiene las credenciales reales de todos los usuarios que iniciaron sesion.",
        "steps": ["Pon UseLogonCredential en 0 y reinicia el equipo.", "Cambia las contrasenas de quienes usaron este equipo."],
        "fix": "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest' -Name UseLogonCredential -Value 0",
        "refs": ["MITRE ATT&CK T1003.001 - Volcado de memoria LSASS", "MITRE ATT&CK T1112"],
    },
    "NTLMV1_ALLOWED": {
        "risk": "NTLMv1 y LM se descifran rapidamente: un atacante en la red captura el hash y recupera la contrasena o la reutiliza.",
        "steps": ["Configura 'Seguridad de red: nivel de autenticacion de LAN Manager' en 'Enviar solo respuesta NTLMv2. Rechazar LM y NTLM'."],
        "fix": "Set-ItemProperty 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' -Name LmCompatibilityLevel -Value 5",
        "refs": ["CIS Benchmark Windows 2.3.11.7", "MITRE ATT&CK T1557.001 - LLMNR/NBT-NS poisoning"],
    },
    "LLMNR_ENABLED": {
        "risk": "LLMNR permite que otro equipo de la red responda haciendose pasar por un servidor y capture hashes de contrasenas (ataque con Responder).",
        "steps": ["Por directiva: Configuracion del equipo > Plantillas administrativas > Red > Cliente DNS > Desactivar resolucion de nombres de multidifusion = Habilitada."],
        "fix": "New-Item 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Force | Out-Null; Set-ItemProperty 'HKLM:\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient' -Name EnableMulticast -Value 0",
        "refs": ["MITRE ATT&CK T1557.001", "CIS Benchmark Windows 18.6.4.4"],
    },
    "DEFENDER_EXCLUSIONS": {
        "risk": "Una exclusion hace que el antivirus ignore una carpeta, programa o tipo de archivo. Los atacantes agregan exclusiones para que su malware no sea escaneado; tambien aparecen por instalaciones descuidadas.",
        "steps": [
            "Revisa cada exclusion en Seguridad de Windows > Proteccion contra virus y amenazas > Exclusiones.",
            "Elimina las que nadie pueda justificar, sobre todo carpetas de usuario, Temp o unidades completas.",
        ],
        "fix": "Remove-MpPreference -ExclusionPath '<ruta>'",
        "refs": ["MITRE ATT&CK T1562.001 - Desactivar o modificar herramientas", "CIS Control 10.1"],
    },
    "AUTORUN_UNSIGNED_USER_PATH": {
        "risk": "Un programa sin firma que arranca con Windows desde una carpeta del usuario (AppData, Temp, Descargas) es la forma mas comun en que el malware se mantiene activo despues de reiniciar.",
        "steps": [
            "Busca el nombre del archivo en VirusTotal o analizalo con Defender (clic derecho > Examinar).",
            "Si no lo reconoces, eliminalo del inicio (Administrador de tareas > Inicio) y borra el archivo.",
        ],
        "fix": "Start-MpScan -ScanType CustomScan -ScanPath '<ruta>'",
        "refs": ["MITRE ATT&CK T1547.001 - Claves Run / carpeta Inicio", "CIS Control 2.7 - Lista de software permitido"],
    },
    "SHARE_OPEN_TO_EVERYONE": {
        "risk": "Una carpeta compartida con 'Todos' puede ser leida o modificada por cualquier equipo de la red. El ransomware cifra justamente estas carpetas para afectar a toda la empresa.",
        "steps": [
            "Abre las propiedades de la carpeta > Compartir > Uso compartido avanzado > Permisos.",
            "Quita 'Todos' y concede acceso solo a los usuarios o grupos necesarios.",
        ],
        "fix": "Revoke-SmbShareAccess -Name '<recurso>' -AccountName 'Everyone' -Force",
        "refs": ["CIS Control 3.3 - Listas de control de acceso", "MITRE ATT&CK T1039 - Datos de recursos compartidos"],
    },
    "RISKY_PORT_LISTENING": {
        "risk": "Un servicio escuchando en todas las interfaces es alcanzable por cualquier equipo de la red, y por Internet si el router lo publica. FTP y Telnet envian contrasenas sin cifrar; VNC y bases de datos suelen tener contrasenas debiles.",
        "steps": [
            "Identifica el programa que abre el puerto (se muestra en el detalle).",
            "Desinstalalo o configuralo para escuchar solo en 127.0.0.1 si no necesita acceso externo.",
            "Bloquea el puerto en el firewall si debe seguir instalado.",
        ],
        "fix": "New-NetFirewallRule -DisplayName 'Bloquear puerto' -Direction Inbound -LocalPort <puerto> -Protocol TCP -Action Block",
        "refs": ["CIS Control 4.8", "MITRE ATT&CK T1133 - Servicios remotos externos"],
    },
    "PROCESS_UNSIGNED_USER_PATH": {
        "risk": "Un programa en ejecucion, sin firma digital y lanzado desde una carpeta del usuario o Temp, es el patron tipico de malware, troyanos de acceso remoto y mineros de criptomonedas.",
        "steps": [
            "Ubica el archivo en la ruta indicada y analizalo con Defender o VirusTotal.",
            "Si es desconocido, termina el proceso, borra el archivo y ejecuta un analisis completo.",
        ],
        "fix": "Stop-Process -Id <PID> -Force; Start-MpScan -ScanType FullScan",
        "refs": ["MITRE ATT&CK T1204.002 - Ejecucion de archivo malicioso", "MITRE ATT&CK T1036 - Enmascaramiento"],
    },
    "OS_END_OF_SUPPORT": {
        "risk": "Microsoft ya no publica parches de seguridad para esta version de Windows. Cada vulnerabilidad nueva queda abierta para siempre en este equipo.",
        "steps": [
            "Actualiza a una version de Windows con soporte (Configuracion > Windows Update > Actualizar a la ultima version).",
            "Si el hardware no lo permite, planifica el reemplazo del equipo o contrata actualizaciones extendidas (ESU).",
        ],
        "fix": None,
        "refs": ["CIS Control 2.2 - Software con soporte", "CIS Control 7.3"],
    },
    "BRUTE_FORCE_LOGON": {
        "risk": "Muchos inicios de sesion fallidos seguidos indican que alguien esta intentando adivinar contrasenas. Si una cuenta tiene una contrasena debil, el atacante entrara.",
        "steps": [
            "Verifica si la IP de origen pertenece a la empresa; si es externa, bloqueala en el firewall o router.",
            "Cambia la contrasena de la cuenta atacada por una larga y unica.",
            "Activa el bloqueo de cuenta tras 5-10 intentos y desactiva RDP si no se usa.",
        ],
        "fix": "New-NetFirewallRule -DisplayName 'Bloquear atacante' -Direction Inbound -RemoteAddress <IP> -Action Block",
        "refs": ["MITRE ATT&CK T1110 - Fuerza bruta", "CIS Control 8.2 - Registro de auditoria"],
    },
    "NEW_LOCAL_ACCOUNT": {
        "risk": "Crear cuentas locales es una tecnica comun para mantener acceso despues de una intrusion. Toda cuenta nueva debe tener un responsable conocido.",
        "steps": ["Confirma quien creo la cuenta y para que.", "Si nadie la reconoce, desactivala y revisa el equipo."],
        "fix": "Disable-LocalUser -Name '<cuenta>'",
        "refs": ["MITRE ATT&CK T1136.001 - Crear cuenta local"],
    },
    "ADMIN_GROUP_MEMBER_ADDED": {
        "risk": "Agregar una cuenta al grupo Administradores le da control total del equipo. Es un paso clasico de escalamiento de privilegios durante un ataque.",
        "steps": ["Confirma que el cambio fue autorizado.", "Si no lo fue, retira la cuenta del grupo y revisa quien hizo el cambio."],
        "fix": "Remove-LocalGroupMember -SID S-1-5-32-544 -Member '<SID>'",
        "refs": ["MITRE ATT&CK T1098 - Manipulacion de cuentas", "CIS Control 5.4"],
    },
    "SECURITY_LOG_CLEARED": {
        "risk": "Borrar el registro de seguridad elimina la evidencia de lo ocurrido. Casi nunca es una tarea normal: es una senal fuerte de que un atacante intenta ocultar su actividad.",
        "steps": [
            "Trata el equipo como posiblemente comprometido.",
            "Identifica la cuenta que lo borro (en el detalle) y cambia su contrasena.",
            "Revisa otros equipos donde esa cuenta tenga acceso.",
        ],
        "fix": None,
        "refs": ["MITRE ATT&CK T1070.001 - Borrar registros de eventos", "CIS Control 8 - Gestion de registros"],
    },
    "SUSPICIOUS_SERVICE_INSTALLED": {
        "risk": "Instalar un servicio da ejecucion permanente con privilegios de SYSTEM. Un servicio que apunta a carpetas de usuario, Temp o a PowerShell/cmd es tipico de herramientas de ataque (PsExec, Cobalt Strike).",
        "steps": [
            "Revisa el servicio en services.msc y la ruta del ejecutable.",
            "Si no es reconocido, detenlo, deshabilitalo y analiza el archivo.",
        ],
        "fix": "Stop-Service '<servicio>' -Force; Set-Service '<servicio>' -StartupType Disabled",
        "refs": ["MITRE ATT&CK T1543.003 - Crear servicio de Windows", "MITRE ATT&CK T1569.002 - Ejecucion como servicio"],
    },
    "VULNERABLE_SOFTWARE": {
        "risk": "Cada programa instalado con una version anterior a la correccion tiene una falla publica y documentada. Los atacantes automatizan su explotacion: basta con que el usuario abra un archivo o visite una pagina manipulada. Los programas sin soporte ya no recibiran ninguna correccion.",
        "steps": [
            "Actualiza cada programa listado a la version indicada (o superior) desde el sitio oficial o con winget.",
            "Si es un programa sin soporte, desinstalalo y usa una alternativa vigente.",
            "Tras actualizar, solicita una nueva revision para confirmar que el hallazgo se cierra.",
        ],
        "fix": "winget upgrade --all --include-unknown",
        "refs": ["CIS Control 7.4 - Parches de aplicaciones", "CIS Control 2.2 - Software con soporte", "MITRE ATT&CK T1203 - Explotacion para ejecucion"],
    },
    "EXPLOITED_VULN_UNPATCHED": {
        "risk": "La agencia de ciberseguridad de EE. UU. (CISA) confirmo que estas vulnerabilidades se estan explotando en ataques reales ahora mismo. El parche existe pero este equipo aun no lo instala, asi que es un blanco directo. Es la prioridad numero uno de parcheo.",
        "steps": [
            "Instala hoy mismo las actualizaciones de Windows indicadas en el detalle.",
            "Reinicia el equipo: el parche no protege hasta reiniciar.",
            "Revisa si el equipo mostro actividad extrana antes del parche (procesos o conexiones desconocidas).",
        ],
        "fix": "UsoClient StartInteractiveScan; UsoClient StartDownload; UsoClient StartInstall",
        "refs": ["CISA Known Exploited Vulnerabilities Catalog", "CIS Control 7.3", "MITRE ATT&CK T1190 - Explotar aplicacion expuesta"],
    },
}


def make(
    rule_id: str,
    control: str,
    title: str,
    severity: str,
    triggered: bool,
    evidence: dict[str, Any],
    recommendation: str,
    closure_criteria: str,
    detail: str = "",
    fix_command: str | None = None,
) -> RuleResult:
    knowledge = KNOWLEDGE.get(rule_id, {})
    return RuleResult(
        rule_id=rule_id,
        control=control,
        title=title,
        severity=severity,
        triggered=triggered,
        evidence=evidence,
        recommendation=recommendation,
        closure_criteria=closure_criteria,
        detail=detail,
        risk=knowledge.get("risk", ""),
        steps=tuple(knowledge.get("steps", ())),
        fix_command=fix_command if fix_command is not None else knowledge.get("fix"),
        references=tuple(knowledge.get("refs", ())),
    )


RISKY_SERVICES = {
    "TermService": "Servicios de Escritorio remoto habilitados",
    "RemoteRegistry": "Registro remoto habilitado",
    "WinRM": "Administracion remota WinRM habilitada",
}

RISKY_PORTS = {
    21: ("FTP", "Alto"), 23: ("Telnet", "Alto"), 69: ("TFTP", "Alto"), 5900: ("VNC", "Alto"),
    5901: ("VNC", "Alto"), 6379: ("Redis", "Alto"), 11211: ("Memcached", "Alto"),
    27017: ("MongoDB", "Alto"), 9200: ("Elasticsearch", "Alto"), 1433: ("SQL Server", "Medio"),
    3306: ("MySQL", "Medio"), 5432: ("PostgreSQL", "Medio"),
}
ALL_INTERFACES = {"0.0.0.0", "::", "[::]", "*"}
USER_WRITABLE_MARKERS = (
    "\\appdata\\", "\\temp\\", "\\tmp\\", "\\downloads\\", "\\descargas\\", "\\users\\public\\",
    "\\desktop\\", "\\escritorio\\", "\\programdata\\", "\\$recycle.bin\\",
)
EVERYONE_NAMES = {"everyone", "todos", "jeder", "tout le monde", "todo el mundo"}
LOGON_TYPES = {
    "2": "interactivo (teclado)", "3": "por red (recurso compartido)", "4": "por lotes",
    "5": "de servicio", "7": "desbloqueo de pantalla", "8": "por red con texto claro",
    "10": "escritorio remoto (RDP)", "11": "con credenciales en cache",
}
LOGON_FAILURES = {
    "0xc000006a": "contrasena incorrecta", "0xc0000064": "usuario inexistente",
    "0xc0000234": "cuenta bloqueada", "0xc0000072": "cuenta deshabilitada",
    "0xc0000071": "contrasena expirada", "0xc000006f": "fuera del horario permitido",
    "0xc0000193": "cuenta expirada", "0xc0000070": "equipo no permitido",
}

# Windows client servicing ends per build, per Microsoft's lifecycle pages:
# (Home/Pro end, Enterprise/Education end).
WINDOWS_LIFECYCLE = {
    19044: ("Windows 10 21H2", date(2023, 6, 13), date(2024, 6, 11)),
    19045: ("Windows 10 22H2", date(2025, 10, 14), date(2025, 10, 14)),
    22000: ("Windows 11 21H2", date(2023, 10, 10), date(2024, 10, 8)),
    22621: ("Windows 11 22H2", date(2024, 10, 8), date(2025, 10, 14)),
    22631: ("Windows 11 23H2", date(2025, 11, 11), date(2026, 11, 10)),
    26100: ("Windows 11 24H2", date(2026, 10, 13), date(2027, 10, 12)),
    26200: ("Windows 11 25H2", date(2027, 10, 12), date(2028, 10, 10)),
}


def _bool(value: Any) -> bool:
    return str(value).lower() in {"true", "1", "yes", "enabled", "on"}


def _admin_name(value: Any) -> str:
    text = str(value)
    if "\\" in text:
        text = text.rsplit("\\", 1)[-1]
    return text.strip().lower()


def _int_or_none(value: Any) -> int | None:
    try:
        if value is None or value == "":
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _available(value: Any) -> bool:
    """A failed or unsupported collection cannot prove a control was corrected."""
    if value is None:
        return False
    if isinstance(value, dict):
        if value.get("success") is False or value.get("error"):
            return False
        if value.get("status") in {"error", "unavailable", "not_supported", "not_configured"}:
            return False
    return True


def _module_data(evidence: dict[str, Any], key: str) -> Any:
    """Unwrap results produced by run_module ({success, data, error})."""
    value = evidence.get(key)
    if isinstance(value, dict) and "success" in value and "data" in value:
        return value.get("data") if value.get("success") is True else None
    return value


def _port_number(item: Any) -> int | None:
    value = item.get("port") if isinstance(item, dict) else item
    return _int_or_none(value)


def _user_writable(path: Any) -> bool:
    text = "\\" + str(path or "").lower().replace("/", "\\")
    return any(marker in text for marker in USER_WRITABLE_MARKERS)


def _join(items: list[str], limit: int = 5) -> str:
    shown = items[:limit]
    extra = len(items) - len(shown)
    return "; ".join(shown) + (f" (y {extra} mas)" if extra > 0 else "")


def evaluate_rules(
    evidence: dict[str, Any],
    today: date | None = None,
    kev: dict[str, dict[str, Any]] | None = None,
    msrc: dict[str, Any] | None = None,
) -> list[RuleResult]:
    """``kev`` is the CISA catalog (CVE -> info) and ``msrc`` Microsoft's
    bulletin map; either is None while it is not loaded."""
    today = today or datetime.now(timezone.utc).date()
    results: list[RuleResult] = []
    results += _vulnerability_rules(evidence, kev, msrc)
    results += _firewall_rules(evidence)
    results += _exposure_rules(evidence)
    results += _admin_rules(evidence)
    results += _update_rules(evidence)
    results += _antivirus_rules(evidence)
    results += _device_rules(evidence)
    results += _backup_rules(evidence)
    results += _security_control_rules(evidence)
    results += _hardening_rules(evidence)
    results += _process_rules(evidence)
    results += _lifecycle_rules(evidence, today)
    results += _detection_rules(evidence)
    return results


def _vulnerability_rules(
    evidence: dict[str, Any], kev: dict[str, dict[str, Any]] | None, msrc: dict[str, Any] | None
) -> list[RuleResult]:
    results: list[RuleResult] = []
    kev = kev or {}
    known_exploited = set(kev) | set((msrc or {}).get("exploited", ()))
    software = _module_data(evidence, "software_inventory")
    if isinstance(software, list):
        matches = vulndb.match_software(software)
        exploited = {cve for match in matches for cve in match["cves"] if cve in known_exploited}
        parts = []
        for match in matches:
            if match["eol"] and not match["cves"]:
                parts.append(f"{match['product']} {match['installed']} (sin soporte: ya no recibe parches)")
                continue
            flagged = [
                f"{cve} [EXPLOTADA ACTIVAMENTE - {' y '.join(vulndb.exploited_by(cve, kev, msrc))}]"
                if cve in known_exploited else cve
                for cve in match["cves"]
            ]
            parts.append(
                f"{match['product']} {match['installed']} (corregido en {match['fixed_in']}): {', '.join(flagged)}"
            )
        commands = sorted({f"winget upgrade --id {match['winget_id']}" for match in matches if match["winget_id"]})
        results.append(make(
            "VULNERABLE_SOFTWARE", "software_inventory", "Programas con vulnerabilidades conocidas",
            "Critico" if exploited else "Alto", bool(matches),
            {"programs": [{"product": match["product"], "installed": match["installed"], "fixed_in": match["fixed_in"],
                           "eol": match["eol"], "cves": match["cves"]} for match in matches],
             "exploited_in_wild": sorted(exploited)},
            "Actualizar o desinstalar los programas vulnerables.", "Ningun programa instalado coincide con una vulnerabilidad conocida.",
            ("Programas afectados: " + _join(parts, limit=8) + ".") if matches else "",
            fix_command="\n".join(commands) if commands else None,
        ))

    updates = evidence.get("updates")
    # Without any exploitation catalog loaded we cannot say "not exploited", so
    # the rule is skipped instead of closing an existing finding by mistake.
    if known_exploited and isinstance(updates, dict) and _available(updates) \
            and isinstance(updates.get("pending_updates"), list):
        pending = vulndb.pending_update_cves(updates, msrc)
        hits = [item for item in pending if item["cve"] in known_exploited]
        by_kb: dict[str, list[str]] = {}
        for item in hits:
            by_kb.setdefault(item["kb"] or "sin KB", []).append(item["cve"])
        ransomware = sorted({item["cve"] for item in hits if (kev.get(item["cve"]) or {}).get("ransomware")})
        detail = ""
        if hits:
            detail = (
                "Faltan parches de Windows que corrigen vulnerabilidades explotadas activamente (segun CISA o Microsoft): "
                + _join([f"{kb} -> {', '.join(sorted(set(cves)))}" for kb, cves in by_kb.items()], limit=6) + "."
                + (f" Usadas en campanas de ransomware: {', '.join(ransomware)}." if ransomware else "")
            )
        results.append(make(
            "EXPLOITED_VULN_UNPATCHED", "updates", "Parches pendientes de vulnerabilidades explotadas activamente",
            "Critico", bool(hits),
            {"exploited_cves": sorted({item["cve"] for item in hits}), "kbs": sorted(by_kb), "ransomware_cves": ransomware},
            "Instalar de inmediato las actualizaciones de Windows pendientes.",
            "Ningun parche pendiente corrige vulnerabilidades del catalogo CISA KEV.", detail,
        ))
    return results


def _firewall_rules(evidence: dict[str, Any]) -> list[RuleResult]:
    firewall = evidence.get("firewall")
    if not (isinstance(firewall, dict) and _available(firewall) and firewall.get("public") is not None):
        return []
    public_enabled = _bool(firewall["public"])
    names = {"domain": "Dominio", "private": "Privada", "public": "Publica"}
    off = [names[key] for key in ("domain", "private", "public") if firewall.get(key) is not None and not _bool(firewall[key])]
    detail = (
        f"El firewall de Windows esta APAGADO en los perfiles: {', '.join(off)}. "
        "Cuando el equipo se conecta a una red de ese tipo no filtra ninguna conexion entrante."
        if off else "Los tres perfiles del firewall estan activos."
    )
    return [make(
        "FIREWALL_PUBLIC_DISABLED", "firewall", "Cortafuegos publico desactivado", "Alto",
        not public_enabled, {"public": firewall.get("public"), "disabled_profiles": off},
        "Activar el perfil publico del cortafuegos y verificar nuevamente.",
        "El perfil publico aparece activo en una nueva evidencia.", detail,
    )]


def _exposure_rules(evidence: dict[str, Any]) -> list[RuleResult]:
    results: list[RuleResult] = []
    raw_ports = evidence.get("listening_ports")
    raw_services = evidence.get("services")
    ports = raw_ports if isinstance(raw_ports, list) else []
    services = raw_services if isinstance(raw_services, list) else []
    ports_available = isinstance(raw_ports, list)
    services_available = isinstance(raw_services, list)
    rdp_ports = [item for item in ports if _port_number(item) == 3389]
    port_3389 = bool(rdp_ports)
    term = next(
        (item for item in services if isinstance(item, dict) and str(item.get("name", "")).lower() == "termservice"),
        None,
    )
    term_service = bool(term and _bool(term.get("running", False)))
    # A negative result from only one source cannot disprove a prior positive
    # result from the other source.
    if port_3389 or term_service or (ports_available and services_available):
        parts = []
        if rdp_ports:
            addresses = sorted({str(item.get("address", "?")) for item in rdp_ports if isinstance(item, dict)})
            reach = "todas las interfaces de red" if set(addresses) & ALL_INTERFACES else ", ".join(addresses)
            parts.append(f"El puerto TCP 3389 (Escritorio remoto) esta escuchando en {reach}")
        if term_service:
            parts.append(f"el servicio TermService esta en ejecucion (inicio: {term.get('start_type') or 'desconocido'})")
        detail = ("; ".join(parts) + ". Cualquier equipo que alcance este puerto puede intentar iniciar sesion.") if parts else ""
        results.append(make(
            "RDP_EXPOSED", "ports", "RDP activo o puerto 3389 en escucha local", "Alto",
            port_3389 or term_service, {"port_3389_listening": port_3389, "termservice_running": term_service},
            "Restringir RDP, detenerlo si no se usa o bloquear el puerto segun necesidad.",
            "El servicio o la exposicion deja de cumplir la condicion.", detail,
        ))

    risky = [
        item for item in services
        if isinstance(item, dict) and item.get("name") in RISKY_SERVICES
        and item.get("name") != "TermService" and _bool(item.get("running", False))
    ]
    if services_available and all(isinstance(item, dict) and item.get("running") is not None for item in services):
        detail = _join([
            f"{item['name']} ({RISKY_SERVICES[item['name']].lower()}): {item.get('status', 'Running')}, inicio {item.get('start_type') or 'desconocido'}"
            for item in risky
        ])
        results.append(make(
            "RISKY_SERVICE_ENABLED", "services", "Servicio remoto de riesgo habilitado", "Alto",
            bool(risky), {"services": risky},
            "Deshabilitar servicios remotos que no sean necesarios para la operacion.",
            "Los servicios definidos como riesgo aparecen detenidos o deshabilitados.",
            f"Servicios en ejecucion: {detail}." if risky else "",
        ))

    if ports_available:
        exposed = []
        for item in ports:
            if not isinstance(item, dict):
                continue
            port = _port_number(item)
            if port in RISKY_PORTS and str(item.get("address", "")) in ALL_INTERFACES:
                exposed.append((port, item))
        severity = "Alto" if any(RISKY_PORTS[port][1] == "Alto" for port, _ in exposed) else "Medio"
        detail = _join([
            f"puerto {port} ({RISKY_PORTS[port][0]}) abierto por {item.get('process_name') or 'proceso desconocido'} (PID {item.get('process_id', '?')})"
            for port, item in exposed
        ])
        results.append(make(
            "RISKY_PORT_LISTENING", "ports", "Servicio inseguro escuchando en la red", severity,
            bool(exposed),
            {"exposed": [{"port": port, "service": RISKY_PORTS[port][0], "process": item.get("process_name"),
                          "process_id": item.get("process_id"), "address": item.get("address")} for port, item in exposed]},
            "Cerrar o restringir los servicios que escuchan en todas las interfaces.",
            "Los puertos de riesgo dejan de escuchar en todas las interfaces.",
            f"Escuchando en todas las interfaces: {detail}." if exposed else "",
        ))
    return results


def _admin_rules(evidence: dict[str, Any]) -> list[RuleResult]:
    admins = evidence.get("local_administrators", evidence.get("local_admins"))
    authorized_admins = evidence.get("authorized_local_admins")
    if not (isinstance(admins, list) and isinstance(authorized_admins, list)):
        return []
    authorized_names = {_admin_name(name) for name in authorized_admins}
    unauthorized = [name for name in admins if _admin_name(name) not in authorized_names]
    detail = (
        f"El grupo Administradores contiene {len(unauthorized)} cuenta(s) fuera de la lista autorizada: "
        f"{', '.join(map(str, unauthorized))}. Autorizadas: {', '.join(map(str, authorized_admins)) or 'ninguna'}."
        if unauthorized else ""
    )
    return [make(
        "UNAUTHORIZED_LOCAL_ADMIN", "administrators", "Cuenta no autorizada como administrador local", "Alto",
        bool(unauthorized), {"unauthorized_accounts": unauthorized},
        "Retirar del grupo Administradores las cuentas que no esten autorizadas.",
        "La cuenta ya no aparece dentro del grupo Administradores.", detail,
    )]


def _update_rules(evidence: dict[str, Any]) -> list[RuleResult]:
    updates = evidence.get("updates")
    if not (isinstance(updates, dict) and _available(updates)):
        return []
    pending_count = _int_or_none(updates.get("pending_count"))
    reboot_pending = updates.get("reboot_pending")
    if pending_count is None or reboot_pending is None:
        return []
    pending = [item for item in updates.get("pending_updates") or [] if isinstance(item, dict)]
    critical = [item for item in pending if str(item.get("severity") or "").lower() in {"critical", "critica", "critico"}]
    security = [item for item in pending if item.get("security")]
    severity = "Critico" if critical else "Alto" if pending_count >= 3 or security else "Medio"
    parts = []
    if pending_count:
        named = _join([
            f"{item.get('kb') or 'sin KB'}: {item.get('title')}" + (f" [{item['severity']}]" if item.get("severity") else "")
            for item in pending
        ], limit=6)
        parts.append(f"Faltan {pending_count} actualizacion(es)" + (f", {len(security)} de seguridad" if security else "") + (f": {named}" if named else ""))
    if _bool(reboot_pending):
        parts.append("Hay un reinicio pendiente: parches ya descargados no estan protegiendo al equipo hasta reiniciar")
    return [make(
        "UPDATES_PENDING", "updates", "Actualizaciones pendientes", severity,
        pending_count > 0 or _bool(reboot_pending),
        {"pending_count": pending_count, "reboot_pending": reboot_pending, "pending_updates": pending},
        "Instalar actualizaciones pendientes y reiniciar cuando corresponda.",
        "No quedan pendientes y no existe reinicio requerido segun nueva consulta.",
        ". ".join(parts) + "." if parts else "",
    )]


def _antivirus_rules(evidence: dict[str, Any]) -> list[RuleResult]:
    antivirus = evidence.get("antivirus")
    if not (isinstance(antivirus, dict) and _available(antivirus)):
        return []
    results: list[RuleResult] = []
    preferences = antivirus.get("preferences")
    extended_status_available = isinstance(preferences, dict) or all(
        isinstance(antivirus.get(key), bool)
        for key in ("on_access_protection", "behavior_monitor", "ioav_protection")
    )
    base_status_available = antivirus.get("enabled") is not None and antivirus.get("real_time") is not None
    base_protection_bad = base_status_available and (
        not _bool(antivirus["enabled"]) or not _bool(antivirus["real_time"])
    )
    if base_status_available and (base_protection_bad or extended_status_available):
        preferences = preferences if isinstance(preferences, dict) else {}
        problems = []
        if not _bool(antivirus.get("enabled")):
            problems.append("el motor antivirus esta apagado")
        if not _bool(antivirus.get("real_time")):
            problems.append("la proteccion en tiempo real esta apagada")
        if antivirus.get("on_access_protection") is False:
            problems.append("la proteccion al abrir archivos esta apagada")
        if antivirus.get("behavior_monitor") is False:
            problems.append("el monitor de comportamiento esta apagado")
        if antivirus.get("ioav_protection") is False:
            problems.append("no se escanean descargas ni adjuntos")
        for key, label in (
            ("DisableRealtimeMonitoring", "tiempo real"),
            ("DisableBehaviorMonitoring", "monitor de comportamiento"),
            ("DisableIOAVProtection", "escaneo de descargas"),
        ):
            if _bool(preferences.get(key, False)):
                problems.append(f"una directiva ({key}=True) desactiva {label}")
        if antivirus.get("tamper_protected") is False:
            tamper = " Ademas la Proteccion contra alteraciones esta apagada, por lo que un malware puede desactivarlo."
        else:
            tamper = ""
        results.append(make(
            "ANTIVIRUS_DISABLED", "antivirus", "Antivirus o proteccion en tiempo real desactivada", "Critico",
            bool(problems),
            {
                "name": antivirus.get("name"), "enabled": antivirus.get("enabled"),
                "real_time": antivirus.get("real_time"), "on_access_protection": antivirus.get("on_access_protection"),
                "behavior_monitor": antivirus.get("behavior_monitor"), "ioav_protection": antivirus.get("ioav_protection"),
                "tamper_protected": antivirus.get("tamper_protected"), "preferences": preferences,
            },
            "Activar la proteccion antivirus y la proteccion en tiempo real.",
            "El antivirus y la proteccion en tiempo real aparecen activos.",
            f"{antivirus.get('name') or 'El antivirus'}: {'; '.join(problems)}.{tamper}" if problems else "",
        ))
    signature_age = _int_or_none(antivirus.get("signature_age_days"))
    if signature_age is not None:
        results.append(make(
            "ANTIVIRUS_SIGNATURES_OLD", "antivirus", "Firmas del antivirus desactualizadas", "Alto",
            signature_age > 7,
            {"signature_age_days": signature_age, "signature_last_updated": antivirus.get("signature_last_updated"),
             "signatures_out_of_date": antivirus.get("signatures_out_of_date")},
            "Actualizar las firmas del antivirus desde Seguridad de Windows o Windows Update.",
            "La edad de firmas aparece en siete dias o menos.",
            f"Las firmas tienen {signature_age} dias (ultima actualizacion: {antivirus.get('signature_last_updated') or 'desconocida'}); "
            "lo recomendado es menos de 1 dia." if signature_age > 7 else "",
        ))
    quick_scan_age = _int_or_none(antivirus.get("quick_scan_age_days"))
    if quick_scan_age is not None:
        results.append(make(
            "ANTIVIRUS_SCAN_OLD", "antivirus", "Antivirus sin escaneo reciente", "Medio",
            quick_scan_age > 7,
            {"quick_scan_age_days": quick_scan_age, "quick_scan_end_time": antivirus.get("quick_scan_end_time"),
             "full_scan_age_days": antivirus.get("full_scan_age_days"), "full_scan_end_time": antivirus.get("full_scan_end_time")},
            "Ejecutar un analisis rapido o completo desde Seguridad de Windows y verificar nuevamente.",
            "Existe un escaneo reciente registrado por el antivirus.",
            f"El ultimo analisis rapido fue hace {quick_scan_age} dias ({antivirus.get('quick_scan_end_time') or 'fecha desconocida'})."
            if quick_scan_age > 7 else "",
        ))
    active_threat_count = _int_or_none(antivirus.get("active_threat_count"))
    if active_threat_count is not None:
        threats = [item for item in antivirus.get("threats") or [] if isinstance(item, dict)]
        active = [item for item in threats if item.get("IsActive")] or threats
        severity_names = {1: "baja", 2: "media", 4: "alta", 5: "grave"}
        described = []
        for threat in active:
            resources = threat.get("Resources")
            files = resources if isinstance(resources, list) else ([resources] if resources else [])
            location = f" en {str(files[0]).split('_', 1)[-1]}" if files else ""
            executed = " - SE EJECUTO" if threat.get("DidThreatExecute") else ""
            sev = severity_names.get(_int_or_none(threat.get("SeverityID")) or 0, "")
            described.append(f"{threat.get('ThreatName', 'amenaza')}{f' (gravedad {sev})' if sev else ''}{location}{executed}")
        results.append(make(
            "ANTIVIRUS_ACTIVE_THREATS", "antivirus", "Amenazas activas reportadas por el antivirus", "Critico",
            active_threat_count > 0,
            {"active_threat_count": active_threat_count, "threats": threats},
            "Abrir Seguridad de Windows, revisar Proteccion contra virus y amenazas, aplicar las acciones recomendadas y ejecutar un nuevo escaneo.",
            "El antivirus reporta cero amenazas activas en una nueva evidencia.",
            f"{active_threat_count} amenaza(s) activa(s): {_join(described)}." if active_threat_count > 0 else "",
        ))
    return results


def _device_rules(evidence: dict[str, Any]) -> list[RuleResult]:
    connected = evidence.get("connected_devices")
    if not (isinstance(connected, dict) and _available(connected) and all(
        isinstance(connected.get(key), list) for key in ("usb_storage", "unsigned_drivers", "device_errors")
    )):
        return []
    # Empty card readers report Size=null: there is no media to worry about.
    usb_storage = [
        item for item in connected["usb_storage"]
        if not (isinstance(item, dict) and "Size" in item and not _int_or_none(item.get("Size")))
    ]
    unsigned_drivers = connected["unsigned_drivers"]
    device_errors = connected["device_errors"]

    def describe_usb(item: dict[str, Any]) -> str:
        size = _int_or_none(item.get("Size"))
        serial = str(item.get("SerialNumber") or "").strip()
        return (
            str(item.get("Model") or "USB")
            + (f", {round(size / 1e9)} GB" if size else "")
            + (f", serie {serial}" if serial else "")
        )

    return [
        make(
            "USB_STORAGE_CONNECTED", "connected_devices", "Dispositivo de almacenamiento USB conectado", "Medio",
            bool(usb_storage), {"usb_storage_count": len(usb_storage), "usb_storage": usb_storage},
            "Verificar que el USB sea de confianza y escanearlo con el antivirus antes de abrir archivos.",
            "No aparece almacenamiento USB conectado o el dispositivo fue aprobado por el responsable.",
            "Conectado: " + _join([describe_usb(item) for item in usb_storage if isinstance(item, dict)]) + "."
            if usb_storage else "",
        ),
        make(
            "UNSIGNED_DEVICE_DRIVER", "connected_devices", "Controlador de dispositivo sin firma detectado", "Alto",
            bool(unsigned_drivers), {"unsigned_driver_count": len(unsigned_drivers), "unsigned_drivers": unsigned_drivers},
            "Actualizar o retirar controladores sin firma desde el fabricante oficial.",
            "No aparecen controladores sin firma en una nueva verificacion.",
            "Sin firma: " + _join([
                f"{item.get('DeviceName')} de {item.get('Manufacturer') or 'fabricante desconocido'} (v{item.get('DriverVersion') or '?'}, {item.get('InfName') or 'inf desconocido'})"
                for item in unsigned_drivers if isinstance(item, dict)
            ]) + "." if unsigned_drivers else "",
        ),
        make(
            "DEVICE_WITH_ERROR", "connected_devices", "Dispositivo conectado con estado de error", "Medio",
            bool(device_errors), {"device_error_count": len(device_errors), "device_errors": device_errors},
            "Revisar el Administrador de dispositivos y corregir o retirar dispositivos con error.",
            "Los dispositivos presentes aparecen con estado OK.",
            "Con error: " + _join([
                f"{item.get('FriendlyName') or item.get('InstanceId')} ({item.get('Class') or 'clase desconocida'}, estado {item.get('Status')})"
                for item in device_errors if isinstance(item, dict)
            ]) + "." if device_errors else "",
        ),
    ]


def _backup_rules(evidence: dict[str, Any]) -> list[RuleResult]:
    backup = evidence.get("backup")
    if not (isinstance(backup, dict) and _available(backup)):
        return []
    exists_value = backup.get("exists")
    days = _int_or_none(backup.get("days_since_last_backup"))
    size = _int_or_none(backup.get("latest_size"))
    if not (exists_value is False or (exists_value is True and days is not None and size is not None)):
        return []
    exists = _bool(exists_value)
    too_old = days is not None and days > 7
    empty = size is not None and size <= 0
    path = backup.get("path") or "la ruta configurada"
    if not exists:
        detail = f"No hay ningun archivo de respaldo en {path}."
    elif empty:
        detail = f"El respaldo mas reciente ({backup.get('latest_file') or 'archivo'}) en {path} esta vacio (0 bytes)."
    elif too_old:
        detail = f"El respaldo mas reciente en {path} ({backup.get('latest_file') or 'archivo'}) tiene {days} dias: se perderia todo lo trabajado desde entonces."
    else:
        detail = ""
    return [make(
        "BACKUP_OLD_OR_MISSING", "backup", "Respaldo inexistente o mayor a siete dias", "Alto",
        (not exists) or too_old or empty,
        {"exists": backup.get("exists"), "days_since_last_backup": days, "latest_size": size, "path": backup.get("path")},
        "Ejecutar un respaldo valido y confirmar que exista un archivo reciente y no vacio.",
        "Existe un archivo de respaldo reciente y no vacio.", detail,
    )]


def _security_control_rules(evidence: dict[str, Any]) -> list[RuleResult]:
    controls = _module_data(evidence, "security_controls")
    if not isinstance(controls, dict):
        return []
    results: list[RuleResult] = []
    uac = controls.get("uac")
    if isinstance(uac, dict) and _available(uac):
        enabled = _int_or_none(uac.get("EnableLUA"))
        if enabled is not None:
            results.append(make(
                "UAC_DISABLED", "security_controls", "Control de cuentas de usuario desactivado", "Alto",
                enabled == 0, {"EnableLUA": enabled},
                "Activar UAC segun la linea base de seguridad de Windows.",
                "Una nueva consulta muestra EnableLUA=1.",
                "El registro HKLM\\...\\Policies\\System muestra EnableLUA=0: UAC esta desactivado por completo." if enabled == 0 else "",
            ))
    smb1 = controls.get("smb1")
    if isinstance(smb1, dict) and _available(smb1):
        state = str(smb1.get("State", "")).lower()
        if state in {"enabled", "disabled"}:
            results.append(make(
                "SMB1_ENABLED", "security_controls", "Protocolo SMBv1 habilitado", "Alto",
                state == "enabled", {"State": smb1.get("State")},
                "Deshabilitar SMBv1 despues de revisar compatibilidad de aplicaciones antiguas.",
                "Una nueva consulta muestra SMB1Protocol deshabilitado.",
                "La caracteristica de Windows SMB1Protocol esta instalada y habilitada." if state == "enabled" else "",
            ))
    rdp = controls.get("rdp")
    if isinstance(rdp, dict):
        raw = rdp.get("raw")
        raw_rdp = raw.get("rdp") if isinstance(raw, dict) else None
        raw_nla = raw.get("nla") if isinstance(raw, dict) else None
        if (
            isinstance(raw_rdp, dict) and _available(raw_rdp)
            and isinstance(raw_nla, dict) and _available(raw_nla)
            and _int_or_none(raw_rdp.get("fDenyTSConnections")) is not None
            and _int_or_none(raw_nla.get("UserAuthentication")) is not None
        ):
            rdp_enabled = _int_or_none(raw_rdp["fDenyTSConnections"]) == 0
            nla_required = _int_or_none(raw_nla["UserAuthentication"]) == 1
            results.append(make(
                "RDP_NLA_DISABLED", "security_controls", "RDP activo sin autenticacion de nivel de red", "Alto",
                rdp_enabled and not nla_required, {"rdp_enabled": rdp_enabled, "nla_required": nla_required},
                "Exigir Network Level Authentication para conexiones RDP.",
                "Una nueva consulta confirma RDP deshabilitado o NLA obligatorio.",
                "Escritorio remoto esta permitido (fDenyTSConnections=0) y UserAuthentication=0: no se exige NLA."
                if rdp_enabled and not nla_required else "",
            ))
    volumes = controls.get("bitlocker")
    if isinstance(volumes, list) and volumes:
        system = next(
            (item for item in volumes if isinstance(item, dict) and str(item.get("MountPoint", "")).upper().startswith("C:")),
            None,
        )
        if system is not None and system.get("ProtectionStatus") is not None:
            protection = str(system.get("ProtectionStatus")).lower()
            protected = protection in {"1", "on"}
            results.append(make(
                "BITLOCKER_OFF", "security_controls", "Disco del sistema sin cifrar", "Alto",
                not protected,
                {"mount_point": system.get("MountPoint"), "protection_status": system.get("ProtectionStatus"),
                 "volume_status": system.get("VolumeStatus"), "encryption_percentage": system.get("EncryptionPercentage")},
                "Activar BitLocker en la unidad del sistema.", "BitLocker aparece con proteccion activa en C:.",
                f"La unidad C: no tiene BitLocker activo (proteccion: {system.get('ProtectionStatus')}, "
                f"cifrado: {system.get('EncryptionPercentage', 0)}%)." if not protected else "",
            ))
    secure_boot = controls.get("secure_boot")
    if isinstance(secure_boot, bool):
        results.append(make(
            "SECURE_BOOT_OFF", "security_controls", "Arranque seguro (Secure Boot) desactivado", "Medio",
            not secure_boot, {"secure_boot": secure_boot},
            "Activar Secure Boot en la configuracion UEFI.", "Confirm-SecureBootUEFI devuelve True.",
            "El firmware UEFI reporta Secure Boot desactivado." if not secure_boot else "",
        ))
    return results


def _hardening_rules(evidence: dict[str, Any]) -> list[RuleResult]:
    hardening = _module_data(evidence, "hardening")
    if not isinstance(hardening, dict):
        return []
    results: list[RuleResult] = []

    accounts = hardening.get("accounts")
    if isinstance(accounts, list):
        by_rid = {str(item.get("Sid", "")).rsplit("-", 1)[-1]: item for item in accounts if isinstance(item, dict)}
        guest = by_rid.get("501")
        if guest is not None:
            results.append(make(
                "GUEST_ACCOUNT_ENABLED", "hardening", "Cuenta Invitado habilitada", "Alto",
                bool(guest.get("Enabled")), {"account": guest.get("Name"), "enabled": guest.get("Enabled")},
                "Desactivar la cuenta Invitado.", "La cuenta Invitado aparece deshabilitada.",
                f"La cuenta integrada '{guest.get('Name')}' (Invitado) esta habilitada." if guest.get("Enabled") else "",
            ))
        builtin = by_rid.get("500")
        if builtin is not None:
            results.append(make(
                "BUILTIN_ADMIN_ENABLED", "hardening", "Cuenta Administrador integrada habilitada", "Medio",
                bool(builtin.get("Enabled")),
                {"account": builtin.get("Name"), "enabled": builtin.get("Enabled"), "last_logon": builtin.get("LastLogon")},
                "Desactivar la cuenta Administrador integrada.", "La cuenta integrada aparece deshabilitada.",
                f"La cuenta integrada '{builtin.get('Name')}' esta habilitada"
                f"{' (ultimo inicio: ' + str(builtin.get('LastLogon')) + ')' if builtin.get('LastLogon') else ''}."
                if builtin.get("Enabled") else "",
            ))
        no_password = [
            item for item in accounts
            if isinstance(item, dict) and item.get("Enabled") and item.get("PasswordRequired") is False
            and str(item.get("Sid", "")).rsplit("-", 1)[-1] not in {"501", "503", "504"}
        ]
        results.append(make(
            "ACCOUNT_NO_PASSWORD_REQUIRED", "hardening", "Cuenta habilitada que no requiere contrasena", "Alto",
            bool(no_password), {"accounts": [item.get("Name") for item in no_password]},
            "Exigir contrasena en todas las cuentas habilitadas.", "Todas las cuentas habilitadas requieren contrasena.",
            f"Cuentas habilitadas con PasswordRequired=False: {', '.join(str(item.get('Name')) for item in no_password)}."
            if no_password else "",
        ))

    policy = hardening.get("password_policy")
    if isinstance(policy, dict) and _available(policy) and policy.get("MinimumPasswordLength") is not None:
        min_length = _int_or_none(policy.get("MinimumPasswordLength")) or 0
        lockout = _int_or_none(policy.get("LockoutBadCount")) or 0
        problems = []
        if min_length < 8:
            problems.append(f"longitud minima de contrasena = {min_length} caracteres (recomendado 12 o mas)")
        if lockout == 0:
            problems.append("no hay bloqueo de cuenta por intentos fallidos (se pueden probar contrasenas sin limite)")
        results.append(make(
            "PASSWORD_POLICY_WEAK", "hardening", "Politica de contrasenas debil", "Medio",
            bool(problems), {"MinimumPasswordLength": min_length, "LockoutBadCount": lockout,
                             "MaximumPasswordAge": policy.get("MaximumPasswordAge")},
            "Exigir contrasenas de 12+ caracteres y bloqueo tras intentos fallidos.",
            "La politica local cumple longitud minima y umbral de bloqueo.",
            "Politica local: " + "; ".join(problems) + "." if problems else "",
        ))

    registry = hardening.get("registry")
    if isinstance(registry, dict) and _available(registry):
        wdigest = _int_or_none(registry.get("WDigestUseLogonCredential"))
        results.append(make(
            "WDIGEST_PLAINTEXT", "hardening", "Contrasenas guardadas en texto plano en memoria (WDigest)", "Critico",
            wdigest == 1, {"UseLogonCredential": wdigest},
            "Desactivar WDigest UseLogonCredential.", "UseLogonCredential vale 0 o no existe.",
            "HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\WDigest\\UseLogonCredential = 1." if wdigest == 1 else "",
        ))
        lm_level = _int_or_none(registry.get("LmCompatibilityLevel"))
        results.append(make(
            "NTLMV1_ALLOWED", "hardening", "Autenticacion LM/NTLMv1 permitida", "Alto",
            lm_level is not None and lm_level < 3, {"LmCompatibilityLevel": lm_level},
            "Exigir NTLMv2 (LmCompatibilityLevel 5).", "LmCompatibilityLevel es 3 o mayor.",
            f"LmCompatibilityLevel = {lm_level}: el equipo todavia envia respuestas LM/NTLMv1." if lm_level is not None and lm_level < 3 else "",
        ))
        llmnr = registry.get("LlmnrEnableMulticast")
        llmnr_on = _int_or_none(llmnr) != 0
        results.append(make(
            "LLMNR_ENABLED", "hardening", "Resolucion de nombres LLMNR activa", "Bajo",
            llmnr_on, {"EnableMulticast": llmnr},
            "Desactivar LLMNR por directiva.", "EnableMulticast vale 0.",
            "No existe la directiva EnableMulticast=0, por lo que LLMNR esta activo (valor por defecto de Windows)." if llmnr_on else "",
        ))

    exclusions = hardening.get("defender_exclusions")
    if isinstance(exclusions, dict) and _available(exclusions):
        entries: list[tuple[str, str]] = []
        visible = True
        for key, label in (("ExclusionPath", "carpeta"), ("ExclusionProcess", "proceso"), ("ExclusionExtension", "extension")):
            values = exclusions.get(key) or []
            values = values if isinstance(values, list) else [values]
            for value in values:
                text = str(value)
                if text.upper().startswith("N/A"):
                    visible = False
                    continue
                entries.append((label, text))
        if visible:
            def risky(label: str, value: str) -> bool:
                lowered = value.lower().rstrip("\\")
                return (
                    (label == "carpeta" and (len(lowered) <= 3 or _user_writable(lowered + "\\")))
                    or (label == "proceso" and _user_writable(lowered))
                    or (label == "extension" and lowered.lstrip(".*") in {"exe", "dll", "ps1", "bat", "cmd", "js", "vbs", "scr"})
                )
            dangerous = [(label, value) for label, value in entries if risky(label, value)]
            results.append(make(
                "DEFENDER_EXCLUSIONS", "hardening", "Exclusiones en el antivirus", "Alto" if dangerous else "Medio",
                bool(entries), {"exclusions": [{"type": label, "value": value} for label, value in entries],
                                "dangerous": [value for _, value in dangerous]},
                "Revisar y eliminar exclusiones del antivirus no justificadas.",
                "No quedan exclusiones sin justificar.",
                (f"Defender NO escanea: {_join([f'{label} {value}' for label, value in entries], limit=8)}."
                 + (f" Especialmente peligrosas: {_join([value for _, value in dangerous])}." if dangerous else ""))
                if entries else "",
            ))

    autoruns = hardening.get("autoruns")
    if isinstance(autoruns, list):
        suspicious = [
            item for item in autoruns
            if isinstance(item, dict) and item.get("Path") and _user_writable(item.get("Path"))
            and str(item.get("Signature") or "") not in {"Valid", "FileMissing"}
            and not str(item.get("Path")).lower().endswith(".lnk")
        ]
        results.append(make(
            "AUTORUN_UNSIGNED_USER_PATH", "hardening", "Programa sin firma que inicia con Windows", "Alto",
            bool(suspicious),
            {"entries": [{"name": item.get("Name"), "path": item.get("Path"), "signature": item.get("Signature"),
                          "location": item.get("Location")} for item in suspicious]},
            "Revisar y eliminar programas de inicio no reconocidos.", "No hay programas de inicio sin firma en carpetas de usuario.",
            "Arrancan con Windows: " + _join([
                f"'{item.get('Name')}' -> {item.get('Path')} (firma: {item.get('Signature') or 'ninguna'}; registrado en {item.get('Location')})"
                for item in suspicious
            ]) + "." if suspicious else "",
        ))

    shares = hardening.get("shares")
    if isinstance(shares, list):
        open_shares = []
        writable = False
        for share in shares:
            if not isinstance(share, dict):
                continue
            access = share.get("Access") or []
            access = access if isinstance(access, list) else [access]
            for entry in access:
                account, _, right = str(entry).partition("|")
                if account.split("\\")[-1].strip().lower() in EVERYONE_NAMES:
                    open_shares.append((share, right or "?"))
                    writable = writable or right.lower() in {"full", "change"}
        results.append(make(
            "SHARE_OPEN_TO_EVERYONE", "hardening", "Carpeta compartida abierta a Todos", "Alto" if writable else "Medio",
            bool(open_shares),
            {"shares": [{"name": share.get("Name"), "path": share.get("Path"), "right": right} for share, right in open_shares]},
            "Restringir los permisos de las carpetas compartidas.", "Ninguna carpeta compartida concede acceso a Todos.",
            "Compartido con 'Todos': " + _join([
                f"\\\\equipo\\{share.get('Name')} ({share.get('Path')}) con permiso {right}" for share, right in open_shares
            ]) + "." if open_shares else "",
        ))
    return results


def _process_rules(evidence: dict[str, Any]) -> list[RuleResult]:
    processes = _module_data(evidence, "process_inventory")
    if not isinstance(processes, list):
        return []
    suspicious = [
        item for item in processes
        if isinstance(item, dict) and item.get("executable_path") and _user_writable(item.get("executable_path"))
        and str(item.get("signature_status") or "") != "Valid"
    ]
    return [make(
        "PROCESS_UNSIGNED_USER_PATH", "process_inventory", "Proceso sin firma ejecutandose desde carpeta de usuario", "Alto",
        bool(suspicious),
        {"processes": [{"name": item.get("name"), "pid": item.get("process_id"), "path": item.get("executable_path"),
                        "signature": item.get("signature_status")} for item in suspicious]},
        "Analizar y detener procesos sin firma lanzados desde carpetas de usuario.",
        "No hay procesos sin firma en carpetas de usuario.",
        "En ejecucion: " + _join([
            f"{item.get('name')} (PID {item.get('process_id')}) desde {item.get('executable_path')} - firma: {item.get('signature_status') or 'ninguna'}"
            for item in suspicious
        ]) + "." if suspicious else "",
    )]


def _lifecycle_rules(evidence: dict[str, Any], today: date) -> list[RuleResult]:
    inventory = _module_data(evidence, "system_inventory_v2")
    if not isinstance(inventory, dict):
        return []
    build = _int_or_none(inventory.get("windows_build"))
    edition = str(inventory.get("windows_edition") or (evidence.get("system_info") or {}).get("windows_edition") or "")
    lowered = edition.lower()
    if build is None or "server" in lowered or "ltsc" in lowered or "ltsb" in lowered:
        return []
    known = WINDOWS_LIFECYCLE.get(build)
    if known is None and 10240 <= build < 19044:
        known = (f"Windows 10 (compilacion {build})", date(2022, 6, 14), date(2023, 5, 9))
    if known is None:
        return []
    name, consumer_end, enterprise_end = known
    enterprise = "enterprise" in lowered or "education" in lowered
    end = enterprise_end if enterprise else consumer_end
    expired = today > end
    return [make(
        "OS_END_OF_SUPPORT", "system_inventory_v2", "Version de Windows sin soporte de seguridad", "Critico" if expired else "Bajo",
        expired, {"edition": edition, "build": build, "version": name, "end_of_support": end.isoformat()},
        "Actualizar a una version de Windows con soporte.", "El equipo ejecuta una version con soporte vigente.",
        f"{edition or 'Windows'} - {name} (compilacion {build}) dejo de recibir parches de seguridad el {end.strftime('%d/%m/%Y')}."
        if expired else "",
    )]


def _detection_rules(evidence: dict[str, Any]) -> list[RuleResult]:
    events = evidence.get("security_detections")
    if not isinstance(events, list):
        return []
    events = [item for item in events if isinstance(item, dict)]
    results: list[RuleResult] = []

    failures = [item for item in events if _int_or_none(item.get("event_id")) == 4625]
    groups = Counter(
        (str(item.get("target_user") or "?"), str(item.get("source_ip") or "-"), str(item.get("logon_type") or ""))
        for item in failures
    )
    reasons = Counter(str(item.get("sub_status") or "").lower() for item in failures)
    severity = "Critico" if len(failures) >= 50 else "Alto"
    detail = ""
    if len(failures) >= 10:
        local_sources = {"-", "", "::1", "127.0.0.1"}
        top = [
            f"{count} contra '{user}' desde "
            + ("el propio equipo" if ip in local_sources else ip)
            + f" ({LOGON_TYPES.get(logon, 'tipo ' + logon) if logon else 'tipo desconocido'})"
            for (user, ip, logon), count in groups.most_common(3)
        ]
        cause = ", ".join(
            f"{LOGON_FAILURES.get(reason, reason)}: {count}" for reason, count in reasons.most_common(3) if reason
        )
        detail = f"{len(failures)} inicios de sesion fallidos en las ultimas 24 h: {'; '.join(top)}." + (f" Motivos: {cause}." if cause else "")
    results.append(make(
        "BRUTE_FORCE_LOGON", "security_detections", "Intentos de adivinar contrasenas (fuerza bruta)", severity,
        len(failures) >= 10,
        {"failed_logons": len(failures), "top_sources": [
            {"user": user, "source_ip": ip, "logon_type": logon, "count": count}
            for (user, ip, logon), count in groups.most_common(5)
        ]},
        "Bloquear el origen, reforzar la cuenta atacada y activar bloqueo por intentos.",
        "Sin rafagas de inicios fallidos en las ultimas 24 horas.", detail,
    ))

    created = [item for item in events if _int_or_none(item.get("event_id")) == 4720]
    results.append(make(
        "NEW_LOCAL_ACCOUNT", "security_detections", "Cuenta local creada recientemente", "Medio",
        bool(created), {"accounts": created},
        "Confirmar el origen de las cuentas nuevas.", "Sin cuentas nuevas sin justificar en las ultimas 24 horas.",
        "Creadas: " + _join([
            f"'{item.get('target_user')}' por {item.get('subject_user') or 'desconocido'} el {item.get('time_created')}"
            for item in created
        ]) + "." if created else "",
    ))

    admin_adds = [
        item for item in events
        if _int_or_none(item.get("event_id")) == 4732 and str(item.get("group_sid") or "").endswith("S-1-5-32-544")
    ]
    results.append(make(
        "ADMIN_GROUP_MEMBER_ADDED", "security_detections", "Cuenta agregada al grupo Administradores", "Alto",
        bool(admin_adds), {"changes": admin_adds},
        "Validar el cambio de privilegios.", "Sin cambios no autorizados en Administradores en 24 horas.",
        "Agregados: " + _join([
            f"{item.get('member_sid')} al grupo {item.get('group')} por {item.get('subject_user') or 'desconocido'} el {item.get('time_created')}"
            for item in admin_adds
        ]) + "." if admin_adds else "",
    ))

    cleared = [item for item in events if _int_or_none(item.get("event_id")) == 1102]
    results.append(make(
        "SECURITY_LOG_CLEARED", "security_detections", "Registro de seguridad borrado", "Critico",
        bool(cleared), {"events": cleared},
        "Investigar el borrado del registro de seguridad.", "Sin borrados del registro en las ultimas 24 horas.",
        "Borrado por: " + _join([f"{item.get('subject_user') or 'desconocido'} el {item.get('time_created')}" for item in cleared]) + "."
        if cleared else "",
    ))

    def suspicious_service(item: dict[str, Any]) -> bool:
        command = str(item.get("image_path") or "").strip()
        lowered = command.lower()
        # Only the executable's own location matters; arguments routinely
        # mention ProgramData or user folders (config files, logs).
        if command.startswith('"'):
            executable = command[1:].split('"', 1)[0]
        else:
            executable = command.split(" ", 1)[0]
        return _user_writable(executable) or any(
            token in lowered
            for token in ("powershell", "cmd.exe /c", "cmd /c", "-enc", "mshta", "rundll32", "\\\\127.0.0.1\\admin$")
        )

    services = [item for item in events if _int_or_none(item.get("event_id")) == 7045 and suspicious_service(item)]
    results.append(make(
        "SUSPICIOUS_SERVICE_INSTALLED", "security_detections", "Servicio sospechoso instalado", "Alto",
        bool(services), {"services": services},
        "Revisar servicios instalados desde rutas o comandos inusuales.", "Sin servicios sospechosos en 24 horas.",
        "Instalado: " + _join([
            f"'{item.get('service_name')}' -> {item.get('image_path')} (cuenta {item.get('account') or '?'}, {item.get('time_created')})"
            for item in services
        ]) + "." if services else "",
    ))
    return results
