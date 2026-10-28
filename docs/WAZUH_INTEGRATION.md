# Integración Wazuh: inventario y CVE reales

`app/wazuh_integration.py` consulta dos servicios de Wazuh. El Server API
(`:55000`) proporciona agentes, paquetes instalados y hotfixes. El Indexer API
(`:9200`) proporciona el estado actual de vulnerabilidades desde los índices
que coinciden con `wazuh-states-vulnerabilities*`. El endpoint antiguo
`GET /vulnerability/{agent_id}` fue retirado en Wazuh 4.8.

La integración es de solo lectura. No instala Wazuh ni genera CVE a partir de
versiones por sí misma. Requiere un servidor Wazuh configurado, un indexer
accesible y agentes Wazuh instalados dentro de cada equipo físico o VM.

## Configuración

Definir estas variables en el proceso del backend, usando una cuenta de lectura
para cada API y certificados que validen los nombres de servidor:

| Variable | Uso |
| --- | --- |
| `WAZUH_SERVER_URL` | Origen HTTPS del Server API, por ejemplo `https://wazuh.example:55000` |
| `WAZUH_SERVER_USER`, `WAZUH_SERVER_PASSWORD` | Cuenta del Server API |
| `WAZUH_INDEXER_URL` | Origen HTTPS del Indexer API, por ejemplo `https://indexer.example:9200` |
| `WAZUH_INDEXER_USER`, `WAZUH_INDEXER_PASSWORD` | Cuenta del Indexer API |
| `WAZUH_SERVER_CA_BUNDLE` | Ruta opcional a la CA del Server API |
| `WAZUH_INDEXER_CA_BUNDLE` | Ruta opcional a la CA del Indexer API |

El cliente exige HTTPS y valida TLS. Las rutas de CA permiten confiar en una CA
privada sin desactivar la validación. Los secretos no aparecen en el `repr` de
la configuración. Otorgar a las cuentas únicamente lectura de los agentes e
índices necesarios.

```python
from app.wazuh_integration import WazuhClient, WazuhConfig

with WazuhClient(WazuhConfig.from_env()) as wazuh:
    snapshot = wazuh.fetch_agent_snapshot("001")
```

`snapshot` contiene `agent`, `packages`, `hotfixes` y `vulnerabilities`, con
`source`, `retrieved_at`, `observed_at` cuando Wazuh lo proporciona y el
documento original en `raw`. Cada vulnerabilidad conserva `cve`, nombre y
versión del paquete, severidad, puntuación CVSS y `status` solo si la fuente lo
incluye. Una respuesta incompleta, un error HTTP o un documento ligado a otro
nombre de agente hace fallar toda la lectura; nunca se convierte en una lista
vacía de hallazgos.

La asociación entre un equipo CyberCheck y un agente Wazuh debe guardar el
`wazuh_agent_id` y verificar la identidad del agente antes de publicar datos.
La presencia de un CVE en Wazuh debe mostrarse como evidencia atribuida a
Wazuh. El cierre automático de un hallazgo requiere corroborar inventario,
parches y fecha de observación; la sola desaparición del índice no demuestra
por sí misma una corrección.

## Verificación

`tests/test_wazuh_integration.py` usa un transporte HTTP simulado para cubrir
autenticación, renovación de JWT, paginación, normalización, respuestas
parciales y errores de ambos servicios. No hay pruebas contra un servidor Wazuh
real en este repositorio. Antes de activar la integración en producción, probar
contra la versión concreta de Wazuh instalada y un equipo de laboratorio con
una vulnerabilidad conocida y una corrección verificada.

Fuentes: [Wazuh Server API](https://documentation.wazuh.com/current/user-manual/api/reference.html),
[consulta de vulnerabilidades en Indexer API](https://documentation.wazuh.com/current/user-manual/indexer-api/use-case.html#query-vulnerability-data),
[cambio de API en Wazuh 4.8](https://documentation.wazuh.com/current/release-notes/release-4-8-0.html).
