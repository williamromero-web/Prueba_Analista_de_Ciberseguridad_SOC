#!/usr/bin/env python3
"""
Genera el informe consolidado del pipeline de seguridad de FleetSec S.A.S.

Toma la carpeta donde quedaron los artefactos de todas las etapas, lee la salida
en formato JSON de cada motor y produce un PDF legible, con la misma
presentación del informe ejecutivo del análisis de vulnerabilidades. De paso
escribe un resumen en Markdown para el panel de la ejecución.

Uso:
    python scripts/generar_reporte_seguridad.py \\
        --artefactos artefactos \\
        --salida informe-seguridad-fleetsec.pdf \\
        --resumen resumen.md \\
        --etapa secretos=success \\
        --etapa sast=failure

Las etapas que no se indiquen quedan marcadas como sin dato, de modo que el
informe se puede generar también fuera del pipeline, sobre artefactos guardados.
"""

from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

# Permite ejecutar el archivo directamente, sin instalar el paquete.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from reporte_seguridad import motores  # noqa: E402
from reporte_seguridad.documento import ETAPAS, Informe, resumen_markdown  # noqa: E402


def analizar_argumentos() -> argparse.Namespace:
    analizador = argparse.ArgumentParser(
        description="Genera el informe consolidado del pipeline de seguridad.")
    analizador.add_argument(
        "--artefactos", default="artefactos", type=Path,
        help="Carpeta con los artefactos descargados de la ejecución.")
    analizador.add_argument(
        "--salida", default="informe-seguridad-fleetsec.pdf", type=Path,
        help="Ruta del PDF que se va a generar.")
    analizador.add_argument(
        "--resumen", type=Path,
        help="Ruta opcional donde escribir el resumen en Markdown.")
    analizador.add_argument(
        "--etapa", action="append", default=[], metavar="CLAVE=RESULTADO",
        help="Resultado de una etapa. Se puede repetir una vez por etapa.")
    analizador.add_argument(
        "--demostracion", action="store_true",
        help="Marca el informe como ejecución de demostración, la que incluye "
             "a propósito la versión vulnerable de referencia.")
    return analizador.parse_args()


def leer_resultados(pares: list[str]) -> dict[str, str]:
    """
    Convierte los pares `clave=resultado` en un diccionario.

    Se avisa por consola si llega una clave que no corresponde a ninguna etapa,
    porque casi siempre significa que el pipeline y este script se
    desincronizaron.
    """
    validas = {etapa.clave for etapa in ETAPAS}
    resultados = {}
    for par in pares:
        if "=" not in par:
            print(f"  aviso: se ignora '{par}', falta el signo igual")
            continue
        clave, _, valor = par.partition("=")
        clave, valor = clave.strip(), valor.strip().lower()
        if clave not in validas:
            print(f"  aviso: la etapa '{clave}' no existe en el informe")
            continue
        resultados[clave] = valor
    return resultados


def leer_contexto() -> dict[str, str]:
    """
    Reúne los datos de trazabilidad de la ejecución.

    Los toma de las variables que publica la plataforma. Fuera del pipeline
    quedan vacíos y el informe simplemente no muestra esas filas.
    """
    revision = os.environ.get("GITHUB_SHA", "")
    ejecucion = os.environ.get("GITHUB_RUN_NUMBER", "")
    return {
        "repositorio": os.environ.get("GITHUB_REPOSITORY", ""),
        "rama": os.environ.get("GITHUB_REF_NAME", ""),
        "revision": revision[:12],
        "ejecucion": f"número {ejecucion}" if ejecucion else "",
        "autor": os.environ.get("GITHUB_ACTOR", ""),
        "fecha": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
    }


def main() -> int:
    argumentos = analizar_argumentos()

    print(f"Leyendo los artefactos de {argumentos.artefactos}...")
    if not argumentos.artefactos.exists():
        print("  aviso: la carpeta de artefactos no existe, "
              "el informe se genera sin hallazgos")

    agrupados = motores.recolectar(argumentos.artefactos)
    for motor, lista in agrupados.items():
        print(f"  {motor}: {len(lista)} hallazgos")

    if argumentos.demostracion:
        print("Modo de demostración: el informe se marca como tal.")

    informe = Informe(
        agrupados=agrupados,
        resultados=leer_resultados(argumentos.etapa),
        contexto=leer_contexto(),
        demostracion=argumentos.demostracion,
    )

    argumentos.salida.parent.mkdir(parents=True, exist_ok=True)
    informe.generar(str(argumentos.salida))
    print(f"Informe generado: {argumentos.salida}")

    if argumentos.resumen:
        argumentos.resumen.write_text(resumen_markdown(informe), encoding="utf-8")
        print(f"Resumen generado: {argumentos.resumen}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
