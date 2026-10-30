"""Explanations of every finding in plain Spanish, for people without
technical knowledge (business owners, young or old).

Each entry answers three questions: what is happening, why it matters (with
everyday comparisons) and what to do, and says whether the person can fix it
alone or should ask whoever gives them IT support. The technical diagnosis in
``rules.KNOWLEDGE`` stays available for that support person.
"""
from __future__ import annotations

from typing import Any, Callable

from . import fixes

URGENCY = {
    "Critico": "Urgente: atiéndelo hoy",
    "Alto": "Importante: atiéndelo esta semana",
    "Medio": "Revisar pronto",
    "Bajo": "Recomendación",
}
WHO = {"pasos": "Lo puedes hacer tú", "comando": "Lo puedes hacer tú: tiene solución rápida"}

SECURITY_APP = "Abre el menú Inicio, escribe «Seguridad de Windows» y ábrela."


def _join(values: list[Any], limit: int = 4) -> str:
    items = [str(value) for value in values if value not in (None, "")]
    shown = items[:limit]
    extra = len(items) - len(shown)
    text = ", ".join(shown)
    return text + (f" y {extra} más" if extra > 0 else "")


def _field(items: Any, key: str) -> list[Any]:
    return [item.get(key) for item in items or [] if isinstance(item, dict)]


def _firewall(e: dict[str, Any]) -> str:
    places = {"Publica": "redes públicas (cafeterías, aeropuertos, hoteles)", "Privada": "la red de la casa u oficina",
              "Dominio": "la red de la empresa"}
    off = [places.get(name, name) for name in e.get("disabled_profiles") or []]
    where = f" cuando la computadora se conecta a {_join(off)}" if off else ""
    return f"El firewall —el «portero» de Windows que decide quién puede conectarse a tu computadora— está apagado{where}."


def _services(e: dict[str, Any]) -> str:
    names = {"RemoteRegistry": "Registro remoto", "WinRM": "Administración remota (WinRM)"}
    found = [names.get(name, name) for name in _field(e.get("services"), "name")]
    listed = f": {_join(found)}" if found else ""
    return f"Están encendidas funciones para manejar la computadora desde otra{listed}. Sirven para que un técnico trabaje a distancia."


def _updates(e: dict[str, Any]) -> str:
    count = e.get("pending_count") or 0
    reboot = " La computadora además necesita reiniciarse para terminar de instalar lo que ya descargó." if e.get("reboot_pending") else ""
    if count:
        return f"Hay {count} actualización(es) de Windows sin instalar.{reboot}"
    return f"Windows tiene actualizaciones pendientes.{reboot}"


def _antivirus(e: dict[str, Any]) -> str:
    name = e.get("name") or "El antivirus"
    parts = []
    if e.get("enabled") is False:
        parts.append("está apagado")
    if e.get("real_time") is False:
        parts.append("no revisa los archivos en el momento en que los abres (protección en tiempo real apagada)")
    if e.get("tamper_protected") is False:
        parts.append("cualquier programa podría apagarlo (la «protección contra alteraciones» está desactivada)")
    detail = "; ".join(parts) if parts else "no está protegiendo la computadora por completo"
    return f"{name}: {detail}."


def _threats(e: dict[str, Any]) -> str:
    names = _field(e.get("threats"), "ThreatName")
    count = e.get("active_threat_count") or len(names)
    listed = f": {_join(names)}" if names else ""
    return f"El antivirus encontró {count} programa(s) malicioso(s) que siguen en la computadora{listed}."


def _usb(e: dict[str, Any]) -> str:
    models = _field(e.get("usb_storage"), "Model")
    return f"Hay una memoria o disco USB conectado{': ' + _join(models) if models else ''}."


def _backup(e: dict[str, Any]) -> str:
    path = e.get("path") or "la carpeta de copias"
    if e.get("exists") is False:
        return f"No se encontró ninguna copia de seguridad en {path}."
    if e.get("latest_size") is not None and int(e.get("latest_size") or 0) <= 0:
        return f"La última copia de seguridad en {path} está vacía."
    days = e.get("days_since_last_backup")
    return f"La última copia de seguridad tiene {days} días." if days is not None else "No hay una copia de seguridad reciente."


def _policy(e: dict[str, Any]) -> str:
    parts = []
    length = e.get("MinimumPasswordLength")
    if length is not None and int(length) < 8:
        parts.append(f"Windows acepta contraseñas de solo {length} caracteres" if int(length) else "Windows acepta contraseñas vacías o de cualquier largo")
    if not e.get("LockoutBadCount"):
        parts.append("no bloquea la cuenta aunque alguien se equivoque de contraseña muchísimas veces")
    if not parts:
        return "Las reglas para crear contraseñas son débiles."
    text = " y ".join(parts) + "."
    return text[0].upper() + text[1:]


def _ports(e: dict[str, Any]) -> str:
    items = [
        f"{item.get('process') or 'un programa'} (entrada {item.get('port')}, {item.get('service')})"
        for item in e.get("exposed") or [] if isinstance(item, dict)
    ]
    return f"Estos programas aceptan conexiones desde otras computadoras: {_join(items)}." if items else \
        "Un programa acepta conexiones desde otras computadoras."


def _os(e: dict[str, Any]) -> str:
    version, end = e.get("version"), e.get("end_of_support")
    if version and end:
        year, month, day = str(end).split("-")
        return f"Tu computadora tiene {version}, que dejó de recibir arreglos de seguridad de Microsoft el {day}/{month}/{year}."
    return "Esta versión de Windows ya no recibe arreglos de seguridad de Microsoft."


def _bruteforce(e: dict[str, Any]) -> str:
    sources = [item for item in e.get("top_sources") or [] if isinstance(item, dict)]
    total = e.get("failed_logons") or sum(int(item.get("count") or 0) for item in sources)
    if sources:
        top = sources[0]
        origin = top.get("source_ip")
        where = "desde esta misma computadora" if origin in (None, "", "-") else f"desde la dirección {origin}"
        return f"Hubo {total} intentos fallidos de entrar, la mayoría con la cuenta «{top.get('user')}» {where}, en las últimas 24 horas."
    if total:
        return f"Hubo {total} intentos fallidos de entrar a la computadora en las últimas 24 horas."
    return "Hubo muchos intentos fallidos de entrar a la computadora en poco tiempo."


def _software(e: dict[str, Any]) -> str:
    items = []
    for item in e.get("programs") or []:
        if not isinstance(item, dict):
            continue
        if item.get("eol"):
            items.append(f"{item.get('product')} (ya no tiene soporte: desinstálalo)")
        else:
            items.append(f"{item.get('product')} {item.get('installed')} → actualiza a la versión {item.get('fixed_in')} o más nueva")
    return f"Necesitan atención: {_join(items, 6)}." if items else "Hay programas con fallas de seguridad conocidas."


def _exploited(e: dict[str, Any]) -> str:
    kbs = e.get("kbs") or []
    return (f"Windows tiene pendiente la actualización {_join(kbs)}, que arregla fallas que los delincuentes ya están aprovechando."
            if kbs else "Falta una actualización de Windows que arregla fallas que ya se están aprovechando.")


PLAIN: dict[str, dict[str, Any]] = {
    "FIREWALL_PUBLIC_DISABLED": {
        "title": "La protección de red de Windows está apagada",
        "what": _firewall,
        "why": "Es como dejar la puerta de la casa abierta: cualquier persona conectada a la misma red Wi-Fi podría intentar entrar a tu computadora.",
        "steps": ["Abre el menú Inicio, escribe «Firewall» y entra a «Firewall y protección de red».",
                  "Activa el firewall en las tres opciones: Red de dominio, Red privada y Red pública."],
    },
    "RDP_EXPOSED": {
        "title": "Tu computadora acepta que la manejen a distancia",
        "what": "Está encendido el «Escritorio remoto», que permite controlar esta computadora desde otro lugar.",
        "why": "Los delincuentes buscan computadoras con esta puerta abierta y prueban miles de contraseñas hasta entrar. Es la forma más común en que secuestran la información de las empresas.",
        "steps": ["Si nadie se conecta a esta computadora a distancia, apágalo: Inicio → Configuración → Sistema → Escritorio remoto → Desactivado.",
                  "Si sí lo usan, déjalo encendido solo en las computadoras que lo necesiten y usa contraseñas largas y únicas."],
    },
    "RISKY_SERVICE_ENABLED": {
        "title": "Hay funciones para manejar la computadora a distancia encendidas",
        "what": _services,
        "why": "Si alguien roba una contraseña de la empresa, puede usar estas funciones para meterse en esta computadora sin que nadie lo note.",
        "steps": ["Si en tu empresa nadie maneja esta computadora a distancia, apágalas con la solución rápida de abajo.", "Si un proveedor de soporte sí las usa, confírmalo con él antes."],
    },
    "UNAUTHORIZED_LOCAL_ADMIN": {
        "title": "Hay cuentas con permisos de «jefe» que no deberían tenerlos",
        "what": lambda e: f"Estas cuentas pueden instalar cualquier programa y cambiar toda la configuración: {_join(e.get('unauthorized_accounts') or ['(ver detalle técnico)'])}.",
        "why": "Si a una de esas cuentas le roban la contraseña o abre un archivo con virus, el atacante tendría control total de la computadora.",
        "steps": ["Confirma quién necesita realmente esos permisos.",
                  "Quítaselos a las demás con la solución rápida de abajo; podrán seguir trabajando normal con una cuenta estándar."],
    },
    "UPDATES_PENDING": {
        "title": "Faltan actualizaciones de Windows",
        "what": _updates,
        "why": "Las actualizaciones tapan agujeros de seguridad que los delincuentes ya conocen. Mientras no se instalen, esos agujeros siguen abiertos.",
        "steps": ["Abre Inicio → Configuración → Windows Update.", "Pulsa «Buscar actualizaciones» e instala todo.",
                  "Reinicia la computadora cuando te lo pida."],
    },
    "ANTIVIRUS_DISABLED": {
        "title": "El antivirus está apagado o a medias",
        "what": _antivirus,
        "why": "Sin el antivirus activo, un archivo con virus que llegue por correo o por una memoria USB se abre sin que nada lo detenga.",
        "steps": [SECURITY_APP, "Entra a «Protección contra virus y amenazas» → «Administrar la configuración».",
                  "Activa «Protección en tiempo real» y «Protección contra alteraciones»."],
    },
    "ANTIVIRUS_SIGNATURES_OLD": {
        "title": "El antivirus no se ha actualizado",
        "what": lambda e: f"Su lista de virus conocidos tiene {e.get('signature_age_days', 'varios')} días sin actualizarse.",
        "why": "Cada día aparecen virus nuevos. Con una lista vieja, el antivirus no reconoce los más recientes.",
        "steps": [SECURITY_APP, "Entra a «Protección contra virus y amenazas» y pulsa «Buscar actualizaciones».",
                  "Si no funciona, revisa que la computadora tenga Internet."],
    },
    "ANTIVIRUS_SCAN_OLD": {
        "title": "Hace tiempo que el antivirus no revisa la computadora",
        "what": lambda e: f"El último análisis completo de la computadora fue hace {e.get('quick_scan_age_days', 'varios')} días.",
        "why": "Un virus que entró antes de que se conociera solo se descubre cuando el antivirus vuelve a revisar todo.",
        "steps": [SECURITY_APP, "Entra a «Protección contra virus y amenazas» y pulsa «Examen rápido»."],
    },
    "ANTIVIRUS_ACTIVE_THREATS": {
        "title": "Hay un virus dentro de la computadora",
        "what": _threats,
        "why": "Ese programa podría estar robando contraseñas, espiando lo que haces o dañando archivos en este momento.",
        "steps": ["Desconecta la computadora de Internet (Wi-Fi o cable).", SECURITY_APP,
                  "Entra a «Historial de protección» y elige «Quitar» en cada amenaza; luego haz un «Examen completo».",
                  "Desde OTRA computadora o celular, cambia tus contraseñas importantes (correo, banco).",
                  "Si el antivirus no logra eliminarlo, copia tus archivos importantes a un disco externo y considera reinstalar Windows."],
    },
    "USB_STORAGE_CONNECTED": {
        "title": "Hay una memoria USB conectada",
        "what": _usb,
        "why": "Las memorias USB son una forma común de que entren virus o de que alguien se lleve información de la empresa.",
        "steps": ["Si no la reconoces, desconéctala.",
                  "Si es tuya, revísala con el antivirus antes de abrir sus archivos (clic derecho sobre la memoria → «Examinar con Microsoft Defender»)."],
    },
    "UNSIGNED_DEVICE_DRIVER": {
        "title": "Un aparato usa un programa de control sin garantía del fabricante",
        "what": lambda e: f"El programa que hace funcionar {_join(_field(e.get('unsigned_drivers'), 'DeviceName')) or 'un aparato'} no está firmado por su fabricante.",
        "why": "Estos programas tienen el máximo poder dentro de la computadora; uno falso o dañado podría apagar el antivirus.",
        "steps": ["Busca el nombre del aparato en la página oficial del fabricante y descarga su programa (driver) más reciente.",
                  "Si ese aparato ya no se usa, desconéctalo."],
    },
    "DEVICE_WITH_ERROR": {
        "title": "Un aparato de la computadora está fallando",
        "what": lambda e: f"No funciona bien: {_join(_field(e.get('device_errors'), 'FriendlyName')) or 'un dispositivo'}.",
        "why": "Puede ser una falla del aparato o de su programa de control, y afecta la estabilidad de la computadora.",
        "steps": ["Desconéctalo y vuelve a conectarlo, o reinicia la computadora.",
                  "Si sigue fallando, usa la solución rápida de abajo: abre el «Administrador de dispositivos»; en el aparato con signo amarillo, clic derecho → «Actualizar controlador»."],
    },
    "BACKUP_OLD_OR_MISSING": {
        "title": "No hay una copia de seguridad reciente",
        "what": _backup,
        "why": "Si un virus secuestra tus archivos, se daña el disco o te roban la computadora, la copia de seguridad es lo único que permite recuperar tu información.",
        "steps": ["Haz hoy una copia de tus archivos importantes en un disco externo o en la nube (OneDrive, Google Drive).",
                  "Programa copias automáticas todos los días.",
                  "De vez en cuando, prueba recuperar un archivo para comprobar que la copia sirve."],
    },
    "UAC_DISABLED": {
        "title": "Windows ya no pide permiso antes de cambios importantes",
        "what": "Está apagado el aviso «¿Quieres permitir que esta aplicación haga cambios en el dispositivo?».",
        "why": "Sin ese aviso, cualquier programa —incluido un virus— puede cambiar todo en la computadora sin preguntarte.",
        "steps": ["Abre Inicio y escribe «Cambiar configuración de Control de cuentas de usuario».",
                  "Sube la barra al nivel recomendado, pulsa Aceptar y reinicia."],
    },
    "SMB1_ENABLED": {
        "title": "Hay una forma antigua e insegura de compartir archivos encendida",
        "what": "Está activado «SMB versión 1», un método viejo para compartir carpetas en la red.",
        "why": "Por ahí entró el famoso virus WannaCry, que paralizó empresas y hospitales en todo el mundo.",
        "steps": ["Desactívalo con la solución rápida de abajo y reinicia la computadora.", "Si después una impresora o disco de red muy viejo deja de funcionar, ese aparato necesita actualizarse."],
    },
    "RDP_NLA_DISABLED": {
        "title": "El acceso a distancia tiene una protección apagada",
        "what": "El Escritorio remoto está encendido y no exige identificarse antes de mostrar la pantalla de entrada.",
        "why": "Facilita que alguien pruebe contraseñas una y otra vez, o aproveche fallas antes de identificarse.",
        "steps": ["Si no usas el acceso a distancia, apágalo (Configuración → Sistema → Escritorio remoto).",
                  "Si lo usas: Escritorio remoto → Configuración avanzada → activa «Requerir autenticación a nivel de red»."],
    },
    "BITLOCKER_OFF": {
        "title": "Los archivos del disco no están protegidos con clave",
        "what": "La información del disco C: se puede leer sin contraseña si alguien saca el disco de la computadora.",
        "why": "Si te roban o pierdes la computadora (sobre todo una laptop), cualquiera podría ver tus archivos, correos y contraseñas guardadas.",
        "steps": ["Abre Inicio y escribe «BitLocker» o «Cifrado de dispositivo», y actívalo para el disco C:.",
                  "Guarda la clave de recuperación en un lugar seguro FUERA de la computadora (por ejemplo, en tu cuenta Microsoft)."],
    },
    "SECURE_BOOT_OFF": {
        "title": "Falta una protección del encendido de la computadora",
        "what": "Está apagado el «Arranque seguro» (Secure Boot).",
        "why": "Esa protección impide que un virus se cargue antes que Windows, donde el antivirus no lo puede ver.",
        "steps": ["Usa la solución rápida de abajo: la computadora se reinicia y abre su configuración interna.", "Busca «Secure Boot» (suele estar en la pestaña «Boot» o «Security»), cámbialo a «Enabled», guarda con F10 y confirma."],
    },
    "GUEST_ACCOUNT_ENABLED": {
        "title": "La cuenta de «Invitado» está activa",
        "what": "Cualquier persona puede entrar a la computadora como «Invitado», sin tener cuenta propia.",
        "why": "No sabrías quién usó la computadora, y es una puerta de entrada innecesaria.",
        "steps": ["Desactívala con la solución rápida de abajo."],
    },
    "BUILTIN_ADMIN_ENABLED": {
        "title": "La cuenta «Administrador» que trae Windows está activa",
        "what": lambda e: f"Está habilitada la cuenta «{e.get('account') or 'Administrador'}», que viene de fábrica con Windows.",
        "why": "Su nombre lo conocen todos los atacantes y suele no bloquearse aunque se equivoquen de contraseña muchas veces.",
        "steps": ["Asegúrate de entrar a Windows con tu propia cuenta (no con «Administrador»).", "Desactiva la cuenta de fábrica con la solución rápida de abajo."],
    },
    "ACCOUNT_NO_PASSWORD_REQUIRED": {
        "title": "Hay cuentas que pueden no tener contraseña",
        "what": lambda e: f"Estas cuentas no están obligadas a tener contraseña: {_join(e.get('accounts') or ['(ver detalle técnico)'])}.",
        "why": "Una cuenta sin contraseña es como una puerta sin cerradura: cualquiera entra con solo saber el nombre.",
        "steps": ["Ponle contraseña a cada una de esas cuentas.", "Usa la solución rápida de abajo: obliga a usar contraseña y te pide escribir una nueva para cada cuenta."],
    },
    "PASSWORD_POLICY_WEAK": {
        "title": "Las reglas para las contraseñas son débiles",
        "what": _policy,
        "why": "Las contraseñas cortas se adivinan en minutos, y sin bloqueo un atacante puede probar sin parar.",
        "steps": ["Usa contraseñas de 12 caracteres o más; una frase es fácil de recordar (por ejemplo: «MiCafeConPan2026»).",
                  "Aplica la regla con la solución rápida de abajo: mínimo 12 caracteres y bloqueo después de 10 intentos fallidos."],
    },
    "WDIGEST_PLAINTEXT": {
        "title": "Windows guarda contraseñas sin protección en la memoria",
        "what": "Una configuración antigua hace que las contraseñas de quienes usan la computadora queden a la vista mientras está encendida.",
        "why": "Los delincuentes tienen herramientas que las leen en segundos y las usan para entrar a otras computadoras y servicios de la empresa.",
        "steps": ["Corrígelo hoy con la solución rápida de abajo y reinicia la computadora.",
                  "Después, cambien las contraseñas de quienes usaron esta computadora."],
    },
    "NTLMV1_ALLOWED": {
        "title": "La computadora usa un método viejo para comprobar contraseñas",
        "what": "Acepta un sistema antiguo para verificar contraseñas que es fácil de descifrar.",
        "why": "Alguien conectado a la misma red podría capturar y descubrir contraseñas.",
        "steps": ["Activa el método moderno con la solución rápida de abajo y reinicia la computadora."],
    },
    "LLMNR_ENABLED": {
        "title": "Mejora recomendada en la configuración de red",
        "what": "Está activa una función de Windows (LLMNR) que ayuda a encontrar equipos en la red, pero que un intruso puede aprovechar.",
        "why": "Un equipo malicioso conectado a la misma red podría hacerse pasar por otro y capturar contraseñas. No es urgente.",
        "steps": ["Cuando puedas, desactívala con la solución rápida de abajo. No afecta el uso normal de la red."],
    },
    "DEFENDER_EXCLUSIONS": {
        "title": "El antivirus tiene lugares que no revisa",
        "what": lambda e: f"El antivirus tiene orden de ignorar: {_join(_field(e.get('exclusions'), 'value')) or 'algunas carpetas o programas'}.",
        "why": "Los delincuentes agregan estas «zonas ciegas» para esconder sus programas; también aparecen por instalaciones descuidadas.",
        "steps": ["Si alguien de la empresa las agregó a propósito (por ejemplo, para un programa contable), déjalas.", "Si nadie las reconoce, quítalas con la solución rápida de abajo."],
    },
    "AUTORUN_UNSIGNED_USER_PATH": {
        "title": "Un programa desconocido se abre solo al encender la computadora",
        "what": lambda e: f"Arranca automáticamente un programa sin garantía de su fabricante: {_join(_field(e.get('entries'), 'name')) or 'ver detalle técnico'}.",
        "why": "Así suelen quedarse los virus: se esconden en carpetas personales y se ejecutan cada vez que enciendes la computadora.",
        "steps": ["Si no reconoces el nombre: abre el Administrador de tareas (Ctrl+Shift+Esc) → pestaña «Inicio» → clic derecho → «Deshabilitar».",
                  "O usa la solución rápida de abajo: revisa el archivo con el antivirus y quita su arranque automático."],
    },
    "SHARE_OPEN_TO_EVERYONE": {
        "title": "Hay una carpeta compartida que cualquiera puede abrir",
        "what": lambda e: f"Estas carpetas están compartidas con «Todos» en la red: {_join(_field(e.get('shares'), 'name')) or 'ver detalle técnico'}.",
        "why": "Cualquier equipo de la red puede ver o cambiar esos archivos; si un virus entra a otra computadora, también puede dañarlos.",
        "steps": ["Quita el acceso de «Todos» con la solución rápida de abajo.", "Luego da acceso solo a quien lo necesita: clic derecho en la carpeta → Propiedades → Compartir."],
    },
    "RISKY_PORT_LISTENING": {
        "title": "Un programa acepta conexiones desde otras computadoras",
        "what": _ports,
        "why": "Es una puerta abierta hacia tu computadora. Algunos de estos programas tienen contraseñas débiles o envían datos sin protección.",
        "steps": ["Si no reconoces el programa, desinstálalo (Configuración → Aplicaciones).", "Si lo necesitas, bloquea las conexiones desde otras computadoras con la solución rápida de abajo."],
    },
    "PROCESS_UNSIGNED_USER_PATH": {
        "title": "Hay un programa sospechoso funcionando",
        "what": lambda e: f"Se está ejecutando un programa sin garantía de su fabricante desde una carpeta personal o temporal: {_join(_field(e.get('processes'), 'name')) or 'ver detalle técnico'}.",
        "why": "Es el comportamiento típico de los virus y programas espía.",
        "steps": ["Anota el nombre del programa.", SECURITY_APP + " Entra a «Protección contra virus y amenazas» → «Opciones de examen» → «Examen completo».",
                  "O usa la solución rápida de abajo: cierra el programa y lo revisa con el antivirus."],
    },
    "OS_END_OF_SUPPORT": {
        "title": "Tu versión de Windows ya no recibe protección",
        "what": _os,
        "why": "Es como una casa a la que ya no le cambian las cerraduras: cada falla nueva que se descubra quedará abierta para siempre.",
        "steps": ["Revisa en Configuración → Windows Update si te ofrece actualizar a Windows 11 (es gratis si tu computadora lo permite).",
                  "Si tu computadora no lo permite, planifica cambiarla; mientras tanto, mantén el antivirus activo y no abras archivos de origen desconocido."],
    },
    "BRUTE_FORCE_LOGON": {
        "title": "Alguien está intentando adivinar una contraseña",
        "what": _bruteforce,
        "why": "Si la contraseña es débil, tarde o temprano la persona logrará entrar.",
        "steps": ["Si no fuiste tú equivocándote, cambia esa contraseña por una larga y única.",
                  "Usa la solución rápida de abajo: bloquea a quien intenta entrar y hace que la cuenta se bloquee tras 10 intentos."],
    },
    "NEW_LOCAL_ACCOUNT": {
        "title": "Se creó una cuenta nueva en la computadora",
        "what": lambda e: f"Se creó: {_join(_field(e.get('accounts'), 'target_user')) or 'una cuenta nueva'}.",
        "why": "Los intrusos crean cuentas para poder volver a entrar después. Toda cuenta nueva debe tener un responsable.",
        "steps": ["Confirma quién la creó y para qué.", "Si nadie la reconoce, desactívala con la solución rápida de abajo."],
    },
    "ADMIN_GROUP_MEMBER_ADDED": {
        "title": "Alguien recibió permisos de «jefe» en la computadora",
        "what": lambda e: f"Se agregó una cuenta al grupo de Administradores{(' (lo hizo ' + _join(_field(e.get('changes'), 'subject_user')) + ')') if _field(e.get('changes'), 'subject_user') else ''}.",
        "why": "Con esos permisos se puede hacer cualquier cosa en la computadora; es un paso típico de un ataque.",
        "steps": ["Confirma que el cambio fue autorizado.", "Si no lo fue, quítale esos permisos con la solución rápida de abajo y revisa la computadora con el antivirus."],
    },
    "SECURITY_LOG_CLEARED": {
        "title": "Alguien borró el historial de seguridad de la computadora",
        "what": lambda e: f"Se borró el registro donde Windows anota quién entra y qué pasa{(' (lo hizo ' + _join(_field(e.get('events'), 'subject_user')) + ')') if _field(e.get('events'), 'subject_user') else ''}.",
        "why": "Casi nunca es algo normal: suele hacerlo un intruso para borrar sus huellas.",
        "steps": ["Trata la computadora como posiblemente infectada o invadida.", "Cambia la contraseña de la cuenta que lo borró.",
                  "Revisa toda la computadora con el antivirus usando la solución rápida de abajo."],
    },
    "SUSPICIOUS_SERVICE_INSTALLED": {
        "title": "Se instaló un programa sospechoso que funciona en segundo plano",
        "what": lambda e: f"Se instaló un programa que corre siempre, aunque nadie use la computadora, desde un lugar poco común: {_join(_field(e.get('services'), 'service_name')) or 'ver detalle técnico'}.",
        "why": "Así funcionan muchas herramientas de ataque para mantener el control de la computadora.",
        "steps": ["Si no reconoces ese programa, detenlo con la solución rápida de abajo.", "Luego revisa la computadora con el antivirus."],
    },
    "VULNERABLE_SOFTWARE": {
        "title": "Tienes programas con fallas de seguridad conocidas",
        "what": _software,
        "why": "Basta con abrir un archivo preparado por un delincuente para que entre a la computadora a través de esa falla.",
        "steps": ["Actualiza cada programa a la versión indicada, desde su página oficial.",
                  "Si es un programa que ya no tiene soporte, desinstálalo (Configuración → Aplicaciones)."],
    },
    "EXPLOITED_VULN_UNPATCHED": {
        "title": "Falta una actualización de Windows contra ataques que están ocurriendo ahora",
        "what": _exploited,
        "why": "No es un riesgo teórico: estos ataques están pasando hoy en el mundo.",
        "steps": ["Hoy mismo: Inicio → Configuración → Windows Update → «Buscar actualizaciones» e instala todo.",
                  "Reinicia la computadora al terminar."],
    },
}


def explain(
    rule_id: str, severity: str, evidence: dict[str, Any] | None = None, has_fix: bool | None = None
) -> dict[str, Any] | None:
    """Plain-language explanation for a finding, or None for unknown rules.

    ``has_fix`` says whether a ready-to-paste command exists; by default it is
    worked out from the same evidence.
    """
    entry = PLAIN.get(rule_id)
    if entry is None:
        return None
    if has_fix is None:
        has_fix = fixes.fix_for(rule_id, evidence) is not None
    who = "comando" if has_fix else "pasos"
    what: str | Callable[[dict[str, Any]], str] = entry["what"]
    if callable(what):
        try:
            what = what(evidence or {})
        except (TypeError, ValueError, KeyError, AttributeError):
            what = what({}) if evidence else "Revisa el detalle técnico de este problema."
    return {
        "title": entry["title"],
        "what": what,
        "why": entry["why"],
        "steps": list(entry["steps"]),
        "who": who,
        "who_label": WHO[who],
        "urgency": URGENCY.get(severity, ""),
    }
