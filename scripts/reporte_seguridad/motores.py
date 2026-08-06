"""
Lectura de la salida de cada motor del pipeline.

Hay una función por herramienta. Todas reciben la carpeta donde quedaron los
artefactos descargados, buscan su archivo y devuelven una lista de hallazgos ya
traducidos a la escala común. Si el archivo no existe, porque la etapa no llegó
a ejecutarse, devuelven una lista vacía en lugar de fallar: el informe debe
poder armarse aunque una etapa se haya caído.

Sobre la traducción de severidades, las decisiones que no vienen dadas por la
herramienta quedan documentadas aquí y se imprimen en el informe:

  - Gitleaks no entrega severidad. Un secreto publicado en el repositorio se
    trata siempre como crítico, porque basta con leerlo para usarlo.
  - Semgrep usa ERROR, WARNING e INFO. ERROR se toma como alto y sube a crítico
    cuando la regla declara un impacto alto en sus metadatos.
  - Checkov comunitario no entrega severidad. Los controles se toman como medios,
    salvo los que abren puertos de administración a Internet, que son críticos
    por ser justamente lo que la prueba exige bloquear.
  - Hadolint usa error, warning, info y style, que se mapean directo.
"""

from __future__ import annotations

import json
from pathlib import Path

from .estilo import limpiar, sanear
from .hallazgos import ALTO, BAJO, CRITICO, INFORMATIVO, MEDIO, Hallazgo

# Controles de Checkov que corresponden a un grupo de seguridad que expone un
# puerto de administración a Internet. La prueba pide bloquear exactamente esto.
_CONTROLES_PUERTO_ADMINISTRATIVO = {
    "CKV_AWS_24",   # Acceso al puerto 22 desde 0.0.0.0/0
    "CKV_AWS_25",   # Acceso al puerto 3389 desde 0.0.0.0/0
    "CKV_AWS_260",  # Acceso al puerto 80 desde 0.0.0.0/0
}

_SEVERIDAD_TRIVY = {
    "CRITICAL": CRITICO,
    "HIGH": ALTO,
    "MEDIUM": MEDIO,
    "LOW": BAJO,
    "UNKNOWN": INFORMATIVO,
}

_SEVERIDAD_SEMGREP = {
    "ERROR": ALTO,
    "WARNING": MEDIO,
    "INFO": BAJO,
}

_SEVERIDAD_HADOLINT = {
    "error": ALTO,
    "warning": MEDIO,
    "info": BAJO,
    "style": INFORMATIVO,
}

# Códigos de riesgo de OWASP ZAP.
_SEVERIDAD_ZAP = {
    "3": ALTO,
    "2": MEDIO,
    "1": BAJO,
    "0": INFORMATIVO,
}


def buscar_archivo(carpeta: Path, nombre: str) -> Path | None:
    """
    Busca un archivo por nombre dentro de la carpeta de artefactos.

    La acción que descarga los artefactos deja cada uno en su propio
    subdirectorio, así que la búsqueda es recursiva.
    """
    if not carpeta.exists():
        return None
    for candidato in sorted(carpeta.rglob(nombre)):
        if candidato.is_file():
            return candidato
    return None


def _cargar_json(ruta: Path | None):
    """Lee un JSON y devuelve None si no existe o si está malformado."""
    if ruta is None:
        return None
    try:
        with ruta.open(encoding="utf-8") as archivo:
            return json.load(archivo)
    except (OSError, json.JSONDecodeError) as error:
        print(f"  aviso: no se pudo leer {ruta.name}: {error}")
        return None


def _ubicacion(archivo: object, linea: object) -> str:
    """Arma la referencia de archivo y línea que se imprime en la tabla."""
    ruta = str(archivo or "").lstrip("/")
    if linea in (None, "", 0):
        return sanear(ruta)
    return sanear(f"{ruta}:{linea}")


# ----------------------------------------------------------------------
# Gitleaks
# ----------------------------------------------------------------------

def leer_gitleaks(carpeta: Path) -> list[Hallazgo]:
    """
    Lee el reporte del detector de secretos.

    El valor del secreto se incluye en el detalle porque el reporte es para
    auditoría interna. Si el PDF se comparte fuera, se debe revisar que no
    salgan secretos reales.
    """
    datos = _cargar_json(buscar_archivo(carpeta, "gitleaks-report.json"))
    if not isinstance(datos, list):
        return []

    resultado = []
    for registro in datos:
        regla = registro.get("RuleID") or "secreto"
        secreto = sanear(str(registro.get("Secret", "")).strip() or "(vacío)")
        resultado.append(Hallazgo(
            motor="Gitleaks",
            identificador=sanear(regla),
            titulo=limpiar(registro.get("Description") or "Secreto expuesto en el código"),
            severidad=CRITICO,
            ubicacion=_ubicacion(registro.get("File"), registro.get("StartLine")),
            referencia="CWE-798",
            detalle=f"Valor detectado: {secreto}",
        ))
    return resultado


# ----------------------------------------------------------------------
# Semgrep
# ----------------------------------------------------------------------

def leer_semgrep(carpeta: Path) -> list[Hallazgo]:
    """Lee el reporte del análisis estático de código."""
    datos = _cargar_json(buscar_archivo(carpeta, "semgrep-report.json"))
    if not isinstance(datos, dict):
        return []

    resultado = []
    for registro in datos.get("results", []):
        extra = registro.get("extra", {}) or {}
        metadatos = extra.get("metadata", {}) or {}

        severidad = _SEVERIDAD_SEMGREP.get(str(extra.get("severity", "")).upper(), MEDIO)
        # Una regla marcada como de impacto alto por su autor sube a crítica.
        if severidad == ALTO and str(metadatos.get("impact", "")).upper() == "HIGH":
            severidad = CRITICO

        regla = str(registro.get("check_id", "regla"))
        resultado.append(Hallazgo(
            motor="Semgrep",
            identificador=sanear(regla.split(".")[-1]),
            titulo=limpiar(extra.get("message") or regla),
            severidad=severidad,
            ubicacion=_ubicacion(registro.get("path"),
                                 (registro.get("start") or {}).get("line")),
            referencia=_referencia_semgrep(metadatos),
        ))
    return resultado


def _referencia_semgrep(metadatos: dict) -> str:
    """Toma la primera clasificación CWE u OWASP que declare la regla."""
    for clave in ("cwe", "owasp"):
        valor = metadatos.get(clave)
        if isinstance(valor, list) and valor:
            return limpiar(str(valor[0]).split(":")[0])
        if isinstance(valor, str) and valor:
            return limpiar(valor.split(":")[0])
    return ""


# ----------------------------------------------------------------------
# Trivy, tanto en dependencias como en la imagen del contenedor
# ----------------------------------------------------------------------

def leer_trivy(carpeta: Path, nombres: tuple[str, ...], motor: str) -> list[Hallazgo]:
    """
    Lee uno o varios reportes de Trivy y los junta.

    Sirve para el análisis de dependencias y para el de la imagen, porque ambos
    comparten el mismo esquema. En una ejecución de demostración hay un segundo
    reporte, el de la versión vulnerable de referencia, que se suma al primero.
    """
    resultado = []
    for nombre in nombres:
        resultado.extend(_leer_un_trivy(carpeta, nombre, motor))
    return resultado


def _leer_un_trivy(carpeta: Path, nombre_archivo: str,
                   motor: str) -> list[Hallazgo]:
    datos = _cargar_json(buscar_archivo(carpeta, nombre_archivo))
    if not isinstance(datos, dict):
        return []

    resultado = []
    for bloque in datos.get("Results", []) or []:
        objetivo = bloque.get("Target", "")
        for registro in bloque.get("Vulnerabilities", []) or []:
            puntaje, _ = _cvss_trivy(registro)
            relacion = str(registro.get("Relationship", "") or "").lower()
            etiquetas = []
            if relacion == "direct":
                etiquetas.append("dependencia directa")
            elif relacion == "indirect":
                etiquetas.append("dependencia indirecta")

            paquete = registro.get("PkgName", "")
            instalada = registro.get("InstalledVersion", "")
            corregida = registro.get("FixedVersion", "")

            resultado.append(Hallazgo(
                motor=motor,
                identificador=sanear(registro.get("VulnerabilityID", "")),
                titulo=limpiar(registro.get("Title")
                               or registro.get("Description")
                               or registro.get("VulnerabilityID")),
                severidad=_SEVERIDAD_TRIVY.get(
                    str(registro.get("Severity", "")).upper(), INFORMATIVO),
                ubicacion=sanear(f"{paquete} {instalada}".strip() or objetivo),
                puntaje=f"{puntaje:.1f}" if puntaje else "",
                # La versión que corrige acompaña al título, porque es lo
                # primero que necesita quien va a arreglar la dependencia.
                detalle=sanear(f"corrige en {corregida}" if corregida
                               else "sin versión corregida"),
                etiquetas=etiquetas,
            ))
    return resultado


def _cvss_trivy(registro: dict) -> tuple[float, str]:
    """
    Toma el puntaje CVSS versión 3 del hallazgo.

    Trivy entrega los puntajes de varias fuentes. Se prefiere el del catálogo
    nacional de vulnerabilidades y, si no está, se toma el mayor disponible.
    """
    fuentes = registro.get("CVSS") or {}
    if not isinstance(fuentes, dict):
        return 0.0, ""

    preferida = fuentes.get("nvd") or {}
    if preferida.get("V3Score"):
        return float(preferida["V3Score"]), str(preferida.get("V3Vector", ""))

    mejor, vector = 0.0, ""
    for detalle in fuentes.values():
        if isinstance(detalle, dict) and detalle.get("V3Score"):
            valor = float(detalle["V3Score"])
            if valor > mejor:
                mejor, vector = valor, str(detalle.get("V3Vector", ""))
    return mejor, vector


# ----------------------------------------------------------------------
# Checkov
# ----------------------------------------------------------------------

def leer_checkov(carpeta: Path) -> list[Hallazgo]:
    """
    Lee el reporte de la revisión del código de infraestructura.

    Checkov entrega un objeto por marco de trabajo analizado, o una lista de
    esos objetos cuando encuentra varios. Se contemplan las dos formas.
    """
    datos = _cargar_json(buscar_archivo(carpeta, "checkov-report.json"))
    if datos is None:
        return []

    bloques = datos if isinstance(datos, list) else [datos]
    resultado = []
    for bloque in bloques:
        if not isinstance(bloque, dict):
            continue
        fallidos = ((bloque.get("results") or {}).get("failed_checks") or [])
        for registro in fallidos:
            control = str(registro.get("check_id", ""))
            severidad = (CRITICO if control in _CONTROLES_PUERTO_ADMINISTRATIVO
                         else MEDIO)
            rango = registro.get("file_line_range") or []
            resultado.append(Hallazgo(
                motor="Checkov",
                identificador=sanear(control),
                titulo=limpiar(registro.get("check_name") or control),
                severidad=severidad,
                ubicacion=_ubicacion(registro.get("file_path"),
                                     rango[0] if rango else None),
                # El recurso afectado acompaña al título. La herramienta no
                # entrega una clasificación externa del tipo CWE u OWASP.
                detalle=sanear(registro.get("resource", "")),
            ))
    return resultado


# ----------------------------------------------------------------------
# Hadolint
# ----------------------------------------------------------------------

def leer_hadolint(carpeta: Path) -> list[Hallazgo]:
    """
    Lee los reportes de la revisión de los archivos de construcción.

    En una ejecución de demostración hay dos: el de la aplicación y el de la
    versión vulnerable de referencia. Se leen todos los que existan y se
    juntan, porque cada registro ya dice a qué archivo pertenece.
    """
    resultado = []
    for nombre in ("hadolint-report.json", "hadolint-baseline-report.json"):
        datos = _cargar_json(buscar_archivo(carpeta, nombre))
        if not isinstance(datos, list):
            continue

        for registro in datos:
            resultado.append(Hallazgo(
                motor="Hadolint",
                identificador=sanear(registro.get("code", "")),
                titulo=limpiar(registro.get("message", "")),
                severidad=_SEVERIDAD_HADOLINT.get(
                    str(registro.get("level", "")).lower(), INFORMATIVO),
                ubicacion=_ubicacion(registro.get("file"), registro.get("line")),
            ))
    return resultado


# ----------------------------------------------------------------------
# OWASP ZAP
# ----------------------------------------------------------------------

def leer_zap(carpeta: Path) -> list[Hallazgo]:
    """
    Lee el reporte del escaneo dinámico de la API.

    ZAP agrupa las alertas por sitio y expresa el riesgo con un código numérico.
    Las descripciones vienen con etiquetas de HTML, que se limpian.
    """
    datos = _cargar_json(buscar_archivo(carpeta, "report_json.json"))
    if not isinstance(datos, dict):
        return []

    resultado = []
    for sitio in datos.get("site", []) or []:
        for alerta in sitio.get("alerts", []) or []:
            instancias = alerta.get("instances") or []
            primera = instancias[0] if instancias else {}
            cwe = alerta.get("cweid")
            resultado.append(Hallazgo(
                motor="OWASP ZAP",
                identificador=sanear(alerta.get("pluginid", "")),
                titulo=limpiar(alerta.get("alert") or alerta.get("name")),
                severidad=_SEVERIDAD_ZAP.get(str(alerta.get("riskcode", "0")),
                                             INFORMATIVO),
                ubicacion=sanear(primera.get("uri", sitio.get("@name", ""))),
                referencia=sanear(f"CWE-{cwe}") if cwe and str(cwe) != "-1" else "",
                # La recomendación de arreglo no se copia aquí porque alarga
                # cada fila sin aportar al inventario. Está completa en el
                # reporte en HTML que publica la misma etapa.
            ))
    return resultado


# ----------------------------------------------------------------------
# Recolección completa
# ----------------------------------------------------------------------

def recolectar(carpeta: Path) -> dict[str, list[Hallazgo]]:
    """
    Recorre todos los motores y devuelve sus hallazgos agrupados.

    El orden de las claves es el orden en que aparecen las etapas en el
    pipeline, y es el que se respeta al imprimir el detalle.
    """
    return {
        "Gitleaks": leer_gitleaks(carpeta),
        "Semgrep": leer_semgrep(carpeta),
        "Trivy dependencias": leer_trivy(
            carpeta,
            ("trivy-fs-report.json", "trivy-fs-baseline-report.json"),
            "Trivy dependencias"),
        "Trivy imagen": leer_trivy(
            carpeta,
            ("trivy-image-report.json", "trivy-image-baseline-report.json"),
            "Trivy imagen"),
        "Hadolint": leer_hadolint(carpeta),
        "Checkov": leer_checkov(carpeta),
        "OWASP ZAP": leer_zap(carpeta),
    }
