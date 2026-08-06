"""
Modelo común de un hallazgo y escala de severidad.

Cada motor del pipeline nombra las severidades a su manera: Semgrep habla de
ERROR y WARNING, Trivy de CRITICAL y HIGH, ZAP usa códigos numéricos y Gitleaks
no entrega ninguna. Para poder sumarlos en un mismo cuadro se traduce todo a una
escala única de cinco niveles, y esa traducción queda impresa en el informe para
que cualquiera pueda auditarla.
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Escala única, de mayor a menor gravedad. El orden importa: se usa para
# ordenar los hallazgos y para recorrer las barras del resumen.
CRITICO = "Crítico"
ALTO = "Alto"
MEDIO = "Medio"
BAJO = "Bajo"
INFORMATIVO = "Informativo"

ESCALA = [CRITICO, ALTO, MEDIO, BAJO, INFORMATIVO]

# Severidades que se consideran bloqueantes para el resumen ejecutivo.
BLOQUEANTES = {CRITICO, ALTO}

_PESO = {nivel: posicion for posicion, nivel in enumerate(ESCALA)}


@dataclass
class Hallazgo:
    """Un hallazgo ya traducido a la escala común del informe."""

    motor: str
    """Nombre de la herramienta que lo reportó, tal como aparece en el pipeline."""

    identificador: str
    """Identificador propio del motor: CVE, regla de Semgrep, control de Checkov."""

    titulo: str
    """Descripción corta, la que se imprime en la tabla de detalle."""

    severidad: str
    """Uno de los cinco niveles de la escala común."""

    ubicacion: str = ""
    """Archivo y línea, recurso de infraestructura o ruta de la API."""

    puntaje: str = ""
    """Puntaje CVSS cuando el motor lo entrega. Queda vacío si no aplica."""

    referencia: str = ""
    """Clasificación externa del hallazgo: CWE, OWASP Top 10 o equivalente."""

    detalle: str = ""
    """Explicación extendida. No se imprime en la tabla, alimenta el conteo."""

    etiquetas: list[str] = field(default_factory=list)
    """Marcas adicionales, por ejemplo si la dependencia es directa o indirecta."""


def peso(severidad: str) -> int:
    """Devuelve la posición de una severidad en la escala, para poder ordenar."""
    return _PESO.get(severidad, len(ESCALA))


def ordenar(lista: list[Hallazgo]) -> list[Hallazgo]:
    """Ordena los hallazgos de mayor a menor gravedad y luego por motor."""
    return sorted(lista, key=lambda h: (peso(h.severidad), h.motor, h.titulo))


def contar_por_severidad(lista: list[Hallazgo]) -> dict[str, int]:
    """Cuenta cuántos hallazgos hay en cada nivel de la escala."""
    conteo = {nivel: 0 for nivel in ESCALA}
    for hallazgo in lista:
        if hallazgo.severidad in conteo:
            conteo[hallazgo.severidad] += 1
    return conteo


def contar_bloqueantes(lista: list[Hallazgo]) -> int:
    """Cuenta los hallazgos de severidad crítica o alta."""
    return sum(1 for hallazgo in lista if hallazgo.severidad in BLOQUEANTES)
