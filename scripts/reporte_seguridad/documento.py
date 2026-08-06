"""
Composición del informe consolidado.

Arma el documento en tres bloques: una primera página ejecutiva con el estado
general, la distribución de los hallazgos y el resultado de cada etapa; luego el
detalle por motor; y al final el anexo que explica cómo se leyó cada severidad y
qué regla detiene la integración en cada etapa.
"""

from __future__ import annotations

from dataclasses import dataclass

from . import hallazgos as modelo
from .estilo import COLOR_SEVERIDAD, Celda, Documento, Paleta, sanear

# Cuántos hallazgos se detallan por motor. El conteo del resumen siempre usa el
# total; este límite solo evita que un motor ruidoso alargue el documento.
MAXIMO_DETALLE = 25


def _plural(cantidad: int, singular: str, plural: str) -> str:
    """Concuerda en número el sustantivo que acompaña a una cantidad."""
    return f"{cantidad} {singular if cantidad == 1 else plural}"


@dataclass
class Etapa:
    """Una etapa del pipeline y los motores que la componen."""

    clave: str
    nombre: str
    herramientas: str
    motores: tuple[str, ...]


# Orden en que las etapas aparecen en el pipeline y en el informe.
ETAPAS = (
    Etapa("secretos", "Secretos", "Gitleaks", ("Gitleaks",)),
    Etapa("sast", "Análisis de código", "Semgrep", ("Semgrep",)),
    Etapa("sca", "Dependencias e inventario", "Trivy", ("Trivy dependencias",)),
    Etapa("contenedor", "Contenedor e infraestructura", "Hadolint, Trivy y Checkov",
          ("Hadolint", "Trivy imagen", "Checkov")),
    Etapa("dast", "Escaneo dinámico", "OWASP ZAP", ("OWASP ZAP",)),
)

# Cómo se nombra en el informe el resultado que devuelve la plataforma.
_RESULTADOS = {
    "success": ("Aprobado", Paleta.VERDE),
    "failure": ("Detenido", Paleta.CRITICO),
    "cancelled": ("Cancelado", Paleta.MEDIO),
    "skipped": ("Omitido", Paleta.INFORMATIVO),
}

# Reglas que detienen la integración, para el anexo.
_PUERTAS = (
    ("Secretos",
     "Cualquier secreto detectado en el árbol de trabajo."),
    ("Análisis de código",
     "Cualquier hallazgo de nivel ERROR."),
    ("Dependencias",
     "CVSS 8.0 o más en dependencia directa; 9.0 o más en indirecta."),
    ("Inventario",
     "Se genera el inventario CycloneDX si se supera la puerta anterior."),
    ("Contenedor",
     "Falla crítica en la imagen, o imagen base sin versión fija."),
    ("Infraestructura",
     "Cualquier control incumplido, en especial abrir los puertos 22 o 3389."),
    ("Escaneo dinámico",
     "Los altos detienen la integración; los medios abren un caso etiquetado."),
)

# Cómo se tradujo la severidad de cada motor a la escala común.
_EQUIVALENCIAS_SEVERIDAD = (
    ("Gitleaks", "No entrega severidad", "Crítico en todos los casos"),
    ("Semgrep", "ERROR", "Alto, o crítico si la regla declara impacto alto"),
    ("Semgrep", "WARNING / INFO", "Medio / Bajo"),
    ("Trivy", "CRITICAL / HIGH / MEDIUM / LOW", "Crítico / Alto / Medio / Bajo"),
    ("Hadolint", "error / warning / info / style", "Alto / Medio / Bajo / Informativo"),
    ("Checkov", "No entrega severidad", "Medio, o crítico si abre un puerto de administración"),
    ("OWASP ZAP", "Riesgo 3 / 2 / 1 / 0", "Alto / Medio / Bajo / Informativo"),
)


class Informe:
    """Construye el PDF a partir de los hallazgos y del estado de cada etapa."""

    def __init__(self, agrupados: dict[str, list[modelo.Hallazgo]],
                 resultados: dict[str, str], contexto: dict[str, str],
                 demostracion: bool = False):
        self.agrupados = agrupados
        self.resultados = resultados
        self.contexto = contexto
        # Una ejecución de demostración incluye a propósito la versión
        # vulnerable de referencia, así que termina en rojo por diseño. Se marca
        # en el documento para que nadie la confunda con un fallo real.
        self.demostracion = demostracion
        self.todos = [h for lista in agrupados.values() for h in lista]
        self.conteo = modelo.contar_por_severidad(self.todos)
        self.bloqueantes = modelo.contar_bloqueantes(self.todos)
        self.detenido = any(
            self.resultados.get(etapa.clave) == "failure" for etapa in ETAPAS)

    # ------------------------------------------------------------------

    def generar(self, ruta_salida: str):
        """Arma el documento completo y lo escribe en disco."""
        pdf = Documento(
            titulo="Informe consolidado del pipeline de seguridad",
            subtitulo=self._subtitulo(),
            pie=f"Documento de uso interno - FleetSec S.A.S.   |   "
                f"{self.contexto.get('fecha', '')}",
        )
        pdf.add_page()

        self._indicadores(pdf)
        self._panorama(pdf)
        self._distribucion(pdf)
        self._resultado_por_etapa(pdf)
        self._detalle(pdf)
        self._anexo(pdf)

        pdf.output(ruta_salida)

    def _subtitulo(self) -> str:
        partes = ["Cliente: FleetSec S.A.S."]
        if self.contexto.get("rama"):
            partes.append(f"Rama: {self.contexto['rama']}")
        if self.contexto.get("ejecucion"):
            partes.append(f"Ejecución: {self.contexto['ejecucion']}")
        if self.demostracion:
            partes.append("Ejecución de demostración")
        return "   -   ".join(partes)

    # ------------------------------------------------------------------
    # Primera página
    # ------------------------------------------------------------------

    def _indicadores(self, pdf: Documento):
        estado, color_estado = (
            ("Detenido", Paleta.CRITICO) if self.detenido
            else ("Aprobado", Paleta.VERDE))

        criticos_altos = self.bloqueantes
        color_bloqueantes = Paleta.CRITICO if criticos_altos else Paleta.VERDE

        ejecutadas = sum(
            1 for etapa in ETAPAS
            if self.resultados.get(etapa.clave) in ("success", "failure"))

        pdf.tarjetas([
            ("Estado del pipeline", estado, color_estado),
            ("Hallazgos reunidos", str(len(self.todos)), Paleta.ORO),
            ("Críticos y altos", str(criticos_altos), color_bloqueantes),
            ("Etapas ejecutadas", f"{ejecutadas} de {len(ETAPAS)}", Paleta.ORO),
        ])

    def _panorama(self, pdf: Documento):
        pdf.titulo_seccion("Panorama general")
        if self.demostracion:
            pdf.nota(
                "Ejecución de demostración. Se lanzó a mano con la versión "
                "vulnerable de referencia dentro del alcance, para comprobar "
                "que las puertas del pipeline se disparan de verdad. Los "
                "hallazgos de la carpeta _vulnerable_baseline corresponden a "
                "código que se conserva a propósito y que no se despliega.")
            pdf.ln(2)
        pdf.parrafo(self._texto_panorama())

    def _texto_panorama(self) -> str:
        total = len(self.todos)
        # Los cinco niveles forman su plural agregando una ese.
        detalle = ", ".join(
            _plural(self.conteo[nivel], nivel.lower(), nivel.lower() + "s")
            for nivel in modelo.ESCALA if self.conteo[nivel] > 0)

        frases = [
            "El pipeline de seguridad revisó la aplicación de telemetría de "
            "FleetSec S.A.S. en sus cinco etapas: búsqueda de secretos, análisis "
            "del código, revisión de dependencias con inventario de componentes, "
            "revisión del contenedor y de la infraestructura, y escaneo dinámico "
            "de la API con una sesión iniciada."
        ]

        if total == 0:
            frases.append(
                "Ninguno de los motores reportó hallazgos abiertos en esta "
                "ejecución. El resultado se conserva como evidencia del control "
                "aplicado sobre este cambio.")
        else:
            frases.append(
                f"En total se reunieron {_plural(total, 'hallazgo', 'hallazgos')} "
                f"entre todos los motores, repartidos así: {detalle}.")

        if self.bloqueantes > 0:
            etapas_detenidas = [
                etapa.nombre for etapa in ETAPAS
                if self.resultados.get(etapa.clave) == "failure"]
            if etapas_detenidas:
                frases.append(
                    "La integración quedó detenida en "
                    f"{self._enumerar(etapas_detenidas)}. "
                    "Corregir esos hallazgos es condición para poder desplegar.")
            else:
                frases.append(
                    "Los hallazgos de severidad crítica y alta quedaron por "
                    "debajo del umbral que detiene cada etapa, pero conviene "
                    "atenderlos antes del siguiente paso a producción.")
        elif total > 0:
            frases.append(
                "No hay hallazgos de severidad crítica ni alta. Los restantes "
                "quedan como deuda de seguridad para atender de forma "
                "planificada, sin bloquear la entrega.")

        frases.append(
            "El detalle por motor aparece más adelante y el anexo explica cómo "
            "se tradujo la severidad de cada herramienta a una escala única.")

        return " ".join(frases)

    @staticmethod
    def _enumerar(elementos: list[str]) -> str:
        """Une una lista en prosa: 'a', 'a y b', 'a, b y c'."""
        if len(elementos) == 1:
            return elementos[0]
        return ", ".join(elementos[:-1]) + " y " + elementos[-1]

    def _distribucion(self, pdf: Documento):
        pdf.titulo_seccion("Distribución de los hallazgos por severidad")
        pdf.barras([
            (nivel, self.conteo[nivel], COLOR_SEVERIDAD[nivel])
            for nivel in modelo.ESCALA
        ])

    def _resultado_por_etapa(self, pdf: Documento):
        pdf.titulo_seccion("Resultado por etapa")

        filas = []
        for etapa in ETAPAS:
            propios = self.hallazgos_de(etapa)
            bloqueantes = modelo.contar_bloqueantes(propios)
            texto, color = _RESULTADOS.get(
                self.resultados.get(etapa.clave, ""),
                ("Sin dato", Paleta.INFORMATIVO))

            filas.append([
                Celda(f"  {etapa.nombre}"),
                Celda(f"  {etapa.herramientas}"),
                Celda(str(len(propios)), alineacion="C"),
                Celda(str(bloqueantes),
                      color=Paleta.CRITICO if bloqueantes else Paleta.TEXTO,
                      negrita=bool(bloqueantes), alineacion="C"),
                Celda(texto, color=color, negrita=True, alineacion="C"),
            ])

        pdf.tabla(
            ["  Etapa", "  Herramienta", "Hallazgos", "Crít. y altos", "Resultado"],
            [52, 56, 22, 24, 28],
            filas,
            alineacion_encabezado=["L", "L", "C", "C", "C"],
        )

    def hallazgos_de(self, etapa: Etapa) -> list[modelo.Hallazgo]:
        """Reúne los hallazgos de todos los motores que componen una etapa."""
        reunidos = []
        for motor in etapa.motores:
            reunidos.extend(self.agrupados.get(motor, []))
        return reunidos

    # ------------------------------------------------------------------
    # Detalle
    # ------------------------------------------------------------------

    def _detalle(self, pdf: Documento):
        pdf.add_page()
        pdf.titulo_seccion("Detalle de los hallazgos")

        if not self.todos:
            pdf.parrafo(
                "No hay hallazgos abiertos que detallar. Todas las etapas "
                "terminaron sin reportar problemas sobre el código, las "
                "dependencias, el contenedor, la infraestructura ni la API.")
            return

        pdf.parrafo(
            "Los hallazgos se agrupan por motor y dentro de cada motor van "
            "ordenados de mayor a menor gravedad. La columna de referencia "
            "muestra el puntaje CVSS cuando la herramienta lo entrega, porque "
            "es la medida comparable entre hallazgos, y si no lo hay muestra la "
            "clasificación del catálogo público CWE o del listado de OWASP. "
            "Queda en guion solo cuando la herramienta no publica ninguna de "
            "las dos, como pasa con la revisión del archivo de construcción.")

        for motor, lista in self.agrupados.items():
            if not lista:
                continue
            self._tabla_motor(pdf, motor, lista)

    @staticmethod
    def _referencia(hallazgo: modelo.Hallazgo) -> str:
        """
        Devuelve la clasificación externa que se imprime en la tabla.

        Se prefiere el puntaje CVSS cuando la herramienta lo entrega, porque es
        la medida comparable entre hallazgos. Si no hay puntaje se usa la
        clasificación del catálogo público, CWE o el listado de OWASP. Las
        herramientas que no publican ninguna de las dos, como la revisión del
        archivo de construcción, muestran un guion.
        """
        if hallazgo.puntaje:
            return f"CVSS {hallazgo.puntaje}"
        return hallazgo.referencia or "-"

    def _tabla_motor(self, pdf: Documento, motor: str,
                     lista: list[modelo.Hallazgo]):
        ordenados = modelo.ordenar(lista)
        visibles = ordenados[:MAXIMO_DETALLE]

        pdf.titulo_seccion(
            f"{motor}   ({_plural(len(lista), 'hallazgo', 'hallazgos')})")

        filas = []
        for hallazgo in visibles:
            # El detalle acompaña al título en la misma celda. Es donde aparece,
            # por ejemplo, el valor del secreto que encontró Gitleaks.
            descripcion = hallazgo.titulo
            if hallazgo.detalle:
                descripcion = f"{descripcion} · {hallazgo.detalle}"

            filas.append([
                Celda(f"  {hallazgo.identificador}"),
                Celda(f"  {descripcion}"),
                Celda(hallazgo.severidad,
                      color=COLOR_SEVERIDAD.get(hallazgo.severidad, Paleta.TEXTO),
                      negrita=True, alineacion="C"),
                Celda(self._referencia(hallazgo), alineacion="C"),
                Celda(f"  {hallazgo.ubicacion}"),
            ])

        # La columna de ubicación va holgada porque ahí caen los URLs completos
        # del escaneo dinámico, que son los textos más largos del informe.
        pdf.tabla(
            ["  Identificador", "  Hallazgo", "Severidad", "Referencia", "  Ubicación"],
            [26, 62, 19, 20, 55],
            filas,
            alineacion_encabezado=["L", "L", "C", "C", "L"],
        )

        if len(ordenados) > MAXIMO_DETALLE:
            pdf.ln(1.5)
            pdf.nota(
                f"Se muestran los {MAXIMO_DETALLE} hallazgos más graves de "
                f"{len(ordenados)}. La lista completa está en el artefacto "
                f"en formato JSON de esta misma ejecución.")

    # ------------------------------------------------------------------
    # Anexo
    # ------------------------------------------------------------------

    def _anexo(self, pdf: Documento):
        pdf.add_page()

        pdf.titulo_seccion("Cómo se leyó la severidad de cada motor")
        pdf.parrafo(
            "Cada herramienta nombra la gravedad a su manera y algunas no la "
            "entregan. Para poder sumarlas en un mismo cuadro se tradujo todo a "
            "una escala única de cinco niveles. La tabla deja esa traducción a "
            "la vista para que cualquiera pueda revisarla o discutirla.")

        pdf.tabla(
            ["  Motor", "  Valor que entrega", "  Nivel asignado"],
            [40, 62, 80],
            [[Celda(f"  {motor}"), Celda(f"  {original}"), Celda(f"  {asignado}")]
             for motor, original, asignado in _EQUIVALENCIAS_SEVERIDAD],
        )

        pdf.titulo_seccion("Puertas de calidad aplicadas")
        pdf.parrafo(
            "Estas son las condiciones que detienen la integración. Una etapa "
            "marcada como detenida en el cuadro de la primera página incumplió "
            "la regla que aparece en esta tabla.")

        pdf.tabla(
            ["  Etapa", "  Regla que detiene la integración"],
            [46, 136],
            [[Celda(f"  {etapa}"), Celda(f"  {regla}")] for etapa, regla in _PUERTAS],
        )

        pdf.titulo_seccion("Trazabilidad de esta ejecución")
        pdf.tabla(
            ["  Dato", "  Valor"],
            [46, 136],
            [[Celda(f"  {etiqueta}"), Celda(f"  {valor}")]
             for etiqueta, valor in self._trazabilidad() if valor],
        )

        pdf.ln(2)
        pdf.nota(
            "Este informe se genera solo, dentro del pipeline, a partir de la "
            "salida en formato JSON de cada motor. No se edita a mano, de modo "
            "que lo que aparece aquí es exactamente lo que reportaron las "
            "herramientas en esta ejecución.")

    def _trazabilidad(self) -> list[tuple[str, str]]:
        contexto = self.contexto
        return [
            ("Repositorio", contexto.get("repositorio", "")),
            ("Rama", contexto.get("rama", "")),
            ("Revisión", contexto.get("revision", "")),
            ("Ejecución", contexto.get("ejecucion", "")),
            ("Disparado por", contexto.get("autor", "")),
            ("Fecha de generación", contexto.get("fecha", "")),
        ]


# ----------------------------------------------------------------------
# Resumen para el panel de la plataforma
# ----------------------------------------------------------------------

def resumen_markdown(informe: Informe) -> str:
    """
    Arma el cuadro que se publica en el panel de la ejecución.

    Es el mismo contenido de la primera página del PDF, en un formato que la
    plataforma puede mostrar sin descargar nada.
    """
    lineas = [
        "# Resumen del pipeline de seguridad",
        "",
        f"**Estado:** {'Detenido' if informe.detenido else 'Aprobado'}  ",
        f"**Hallazgos reunidos:** {len(informe.todos)}  ",
        f"**Críticos y altos:** {informe.bloqueantes}",
        "",
        "| Etapa | Herramienta | Hallazgos | Crít. y altos | Resultado |",
        "| :--- | :--- | :---: | :---: | :---: |",
    ]

    for etapa in ETAPAS:
        propios = informe.hallazgos_de(etapa)
        bloqueantes = modelo.contar_bloqueantes(propios)
        texto, _ = _RESULTADOS.get(
            informe.resultados.get(etapa.clave, ""), ("Sin dato", None))
        lineas.append(
            f"| {etapa.nombre} | {etapa.herramientas} | {len(propios)} "
            f"| {bloqueantes} | {texto} |")

    lineas += [
        "",
        "| Severidad | Hallazgos |",
        "| :--- | :---: |",
    ]
    for nivel in modelo.ESCALA:
        lineas.append(f"| {nivel} | {informe.conteo[nivel]} |")

    lineas += [
        "",
        "> El informe completo en PDF está disponible como artefacto de esta "
        "ejecución, con el nombre **informe-seguridad-pdf**.",
    ]
    return "\n".join(lineas)
