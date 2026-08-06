"""
Tokens de diseño y lienzo del informe.

La paleta, la tipografía y los espaciados se tomaron del informe ejecutivo
`vapt/reporte_ejecutivo_vapt.pdf`, midiendo directamente el documento, para que
los dos archivos se lean como piezas de la misma familia: mismo azul
institucional, mismo acento en oro, misma escala de color por severidad y las
mismas medidas de página, tarjetas y tablas.

Las fuentes son las incorporadas de Helvetica, que cubren el alfabeto latino
completo. Aun así todo el texto pasa por `sanear`, porque la salida de las
herramientas puede traer signos que la codificación de esas fuentes no admite.
"""

from __future__ import annotations

import re

from fpdf import FPDF
from fpdf.enums import XPos, YPos

from . import hallazgos


class Paleta:
    """Colores del documento, en RGB."""

    NAVY = (15, 30, 55)            # Azul institucional: banner, títulos y cabeceras.
    ORO = (176, 141, 87)           # Acento: subtítulo y cifras destacadas.
    BLANCO = (255, 255, 255)
    CLARO = (205, 208, 215)        # Texto pequeño sobre fondo azul.
    TEXTO = (30, 30, 30)           # Cuerpo de texto.
    ETIQUETA = (40, 40, 40)        # Etiquetas de las barras.
    SUAVE = (90, 90, 90)           # Pie de página y notas.
    FILA_ALTERNA = (247, 248, 250)  # Fondo de las filas pares de una tabla.
    PISTA = (238, 240, 244)        # Fondo de la barra de severidad.

    # Escala de severidad. Los tres primeros vienen del informe ejecutivo; los
    # dos últimos se agregaron con la misma saturación apagada de la familia.
    CRITICO = (150, 40, 40)
    ALTO = (191, 116, 34)
    MEDIO = (150, 130, 30)
    BAJO = (58, 94, 133)
    INFORMATIVO = (110, 110, 110)

    VERDE = (30, 110, 60)          # Estado conforme o corregido.


# Traducción de la escala de severidad a color.
COLOR_SEVERIDAD = {
    hallazgos.CRITICO: Paleta.CRITICO,
    hallazgos.ALTO: Paleta.ALTO,
    hallazgos.MEDIO: Paleta.MEDIO,
    hallazgos.BAJO: Paleta.BAJO,
    hallazgos.INFORMATIVO: Paleta.INFORMATIVO,
}


class Medidas:
    """Medidas en milímetros, tomadas del informe ejecutivo."""

    MARGEN = 14.0
    ANCHO_UTIL = 182.0
    ALTO_BANNER = 24.0

    TARJETA_ANCHO = 41.0
    TARJETA_ALTO = 20.0
    TARJETA_SEPARACION = 6.0

    LINEA_CUERPO = 5.2
    ALTO_TITULO = 6.0
    SEPARACION_SECCION = 10.0

    BARRA_X = 36.0
    BARRA_ANCHO = 150.0
    BARRA_ALTO = 4.6
    BARRA_SEPARACION = 6.5

    ENCABEZADO_ALTO = 6.5
    FILA_ALTO = 6.4       # Altura mínima de una fila de una sola línea.
    LINEA_TABLA = 4.0     # Interlineado cuando una celda ocupa varias líneas.

    SANGRIA_CELDA = 1.0  # Separación interna que aplica FPDF dentro de una celda.


class Tipografia:
    """Familia y tamaños en puntos."""

    FAMILIA = "Helvetica"
    TITULO = 14
    SUBTITULO = 9
    ETIQUETA_TARJETA = 7
    VALOR_TARJETA = 13
    TITULO_SECCION = 11.5
    CUERPO = 9.7
    ETIQUETA_BARRA = 9
    ENCABEZADO_TABLA = 8.5
    CUERPO_TABLA = 8.3
    NOTA = 8
    PIE = 7


# Signos frecuentes en la salida de las herramientas que no existen en la
# codificación de las fuentes incorporadas. Se cambian por un equivalente
# legible en lugar de dejar que aparezca un signo de interrogación.
_EQUIVALENCIAS = {
    "—": "-", "–": "-", "‒": "-", "−": "-",
    "‘": "'", "’": "'", "‚": "'", "‛": "'",
    "“": '"', "”": '"', "„": '"', "″": '"',
    "…": "...", "•": "-", " ": " ", " ": " ",
    "​": "", "→": "->", "←": "<-", "⇒": "=>",
    "≥": ">=", "≤": "<=", "≠": "!=", "×": "x",
    "✓": "si", "✗": "no", "€": "EUR", "‹": "<", "›": ">",
}

_ETIQUETAS_HTML = re.compile(r"<[^>]+>")
_ESPACIOS = re.compile(r"\s+")


def sanear(texto: object) -> str:
    """
    Deja un texto listo para imprimirse con las fuentes incorporadas.

    Cambia los signos que la codificación no admite por un equivalente legible y
    descarta cualquier resto que siga sin poder representarse.
    """
    if texto is None:
        return ""
    resultado = str(texto)
    for original, reemplazo in _EQUIVALENCIAS.items():
        resultado = resultado.replace(original, reemplazo)
    return resultado.encode("latin-1", "replace").decode("latin-1")


def limpiar(texto: object) -> str:
    """
    Convierte en una sola línea legible el texto que entregan las herramientas.

    Varias de ellas devuelven fragmentos de HTML o descripciones con saltos de
    línea. Se quitan las etiquetas, se colapsan los espacios y se sanea el
    resultado.
    """
    plano = _ETIQUETAS_HTML.sub(" ", str(texto or ""))
    plano = plano.replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
    plano = _ESPACIOS.sub(" ", plano).strip()
    return sanear(plano)


class Celda:
    """Una celda de tabla con su color y su peso tipográfico."""

    __slots__ = ("texto", "color", "negrita", "alineacion")

    def __init__(self, texto, color=None, negrita=False, alineacion="L"):
        self.texto = sanear(texto)
        self.color = color or Paleta.TEXTO
        self.negrita = negrita
        self.alineacion = alineacion


class Documento(FPDF):
    """
    Lienzo del informe.

    Dibuja el banner y el pie de página, y expone las piezas que se repiten a lo
    largo del documento: tarjetas de indicadores, títulos de sección, párrafos
    justificados, barras de severidad y tablas.
    """

    def __init__(self, titulo: str, subtitulo: str, pie: str):
        super().__init__(orientation="P", unit="mm", format="A4")
        self.titulo = sanear(titulo)
        self.subtitulo = sanear(subtitulo)
        self.pie = sanear(pie)
        self.set_title(self.titulo)
        self.set_auto_page_break(auto=True, margin=20.0)
        self.set_margins(Medidas.MARGEN, Medidas.MARGEN, Medidas.MARGEN)

    # ------------------------------------------------------------------
    # Encabezado y pie, que FPDF invoca solos en cada página
    # ------------------------------------------------------------------

    def header(self):
        """La primera página lleva el banner completo; las siguientes, uno delgado."""
        if self.page_no() == 1:
            self._banner_completo()
        else:
            self._banner_delgado()

    def _banner_completo(self):
        self.set_fill_color(*Paleta.NAVY)
        self.rect(0, 0, self.w, Medidas.ALTO_BANNER, style="F")

        self.set_font(Tipografia.FAMILIA, "B", Tipografia.TITULO)
        self.set_text_color(*Paleta.BLANCO)
        self.set_xy(0, 6.5)
        self.cell(self.w, 7, self.titulo, align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_font(Tipografia.FAMILIA, "I", Tipografia.SUBTITULO)
        self.set_text_color(*Paleta.ORO)
        self.set_xy(0, 13.8)
        self.cell(self.w, 5, self.subtitulo, align="C",
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)

        self.set_text_color(*Paleta.TEXTO)
        self.set_xy(Medidas.MARGEN, Medidas.ALTO_BANNER + 14.0)

    def _banner_delgado(self):
        alto = 12.0
        self.set_fill_color(*Paleta.NAVY)
        self.rect(0, 0, self.w, alto, style="F")

        self.set_font(Tipografia.FAMILIA, "B", Tipografia.SUBTITULO)
        self.set_text_color(*Paleta.BLANCO)
        self.set_xy(Medidas.MARGEN, 3.4)
        self.cell(Medidas.ANCHO_UTIL / 2, 5, self.titulo, align="L")

        self.set_font(Tipografia.FAMILIA, "I", Tipografia.PIE)
        self.set_text_color(*Paleta.ORO)
        self.set_xy(Medidas.MARGEN + Medidas.ANCHO_UTIL / 2, 3.7)
        self.cell(Medidas.ANCHO_UTIL / 2, 5, "FleetSec S.A.S.", align="R")

        self.set_text_color(*Paleta.TEXTO)
        self.set_xy(Medidas.MARGEN, alto + 10.0)

    def footer(self):
        self.set_y(-12.0)
        self.set_font(Tipografia.FAMILIA, "I", Tipografia.PIE)
        self.set_text_color(*Paleta.SUAVE)
        self.cell(Medidas.ANCHO_UTIL, 5,
                  f"{self.pie}   |   Página {self.page_no()}", align="C")
        self.set_text_color(*Paleta.TEXTO)

    # ------------------------------------------------------------------
    # Piezas de contenido
    # ------------------------------------------------------------------

    def tarjetas(self, indicadores: list[tuple[str, str, tuple]]):
        """
        Dibuja la fila de indicadores sobre fondo azul.

        Cada indicador es una terna de etiqueta, valor y color del valor. Se
        reparten cuatro por fila con la separación del informe ejecutivo.
        """
        x = Medidas.MARGEN
        y = self.get_y()
        for etiqueta, valor, color in indicadores[:4]:
            self.set_fill_color(*Paleta.NAVY)
            self.rect(x, y, Medidas.TARJETA_ANCHO, Medidas.TARJETA_ALTO, style="F")

            self.set_font(Tipografia.FAMILIA, "", Tipografia.ETIQUETA_TARJETA)
            self.set_text_color(*Paleta.CLARO)
            self.set_xy(x, y + 4.0)
            self.cell(Medidas.TARJETA_ANCHO, 4, sanear(etiqueta), align="C")

            self.set_font(Tipografia.FAMILIA, "B", Tipografia.VALOR_TARJETA)
            self.set_text_color(*color)
            self.set_xy(x, y + 10.5)
            self.cell(Medidas.TARJETA_ANCHO, 6, sanear(valor), align="C")

            x += Medidas.TARJETA_ANCHO + Medidas.TARJETA_SEPARACION

        self.set_text_color(*Paleta.TEXTO)
        self.set_xy(Medidas.MARGEN, y + Medidas.TARJETA_ALTO)

    def titulo_seccion(self, texto: str):
        """Título de sección en azul institucional, con aire por encima."""
        self.ln(Medidas.SEPARACION_SECCION)
        self._asegurar_espacio(Medidas.ALTO_TITULO + Medidas.LINEA_CUERPO)
        self.set_font(Tipografia.FAMILIA, "B", Tipografia.TITULO_SECCION)
        self.set_text_color(*Paleta.NAVY)
        self.set_x(Medidas.MARGEN)
        self.cell(Medidas.ANCHO_UTIL, Medidas.ALTO_TITULO, sanear(texto),
                  new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(*Paleta.TEXTO)
        self.ln(1.2)

    def parrafo(self, texto: str):
        """Párrafo justificado con el interlineado del informe ejecutivo."""
        self.set_font(Tipografia.FAMILIA, "", Tipografia.CUERPO)
        self.set_text_color(*Paleta.TEXTO)
        self.set_x(Medidas.MARGEN)
        self.multi_cell(Medidas.ANCHO_UTIL, Medidas.LINEA_CUERPO,
                        sanear(texto), align="J",
                        new_x=XPos.LMARGIN, new_y=YPos.NEXT)

    def nota(self, texto: str):
        """Aclaración en cuerpo menor y color apagado."""
        self.set_font(Tipografia.FAMILIA, "I", Tipografia.NOTA)
        self.set_text_color(*Paleta.SUAVE)
        self.set_x(Medidas.MARGEN)
        self.multi_cell(Medidas.ANCHO_UTIL, 4.4, sanear(texto), align="L",
                        new_x=XPos.LMARGIN, new_y=YPos.NEXT)
        self.set_text_color(*Paleta.TEXTO)

    def barras(self, series: list[tuple[str, int, tuple]]):
        """
        Dibuja la distribución por severidad como barras horizontales.

        La barra más larga corresponde al valor mayor de la serie y ocupa el
        ancho completo de la pista, igual que en el informe ejecutivo.
        """
        mayor = max((valor for _, valor, _ in series), default=0)
        for etiqueta, valor, color in series:
            self._asegurar_espacio(Medidas.BARRA_SEPARACION + 2)
            y = self.get_y()

            self.set_font(Tipografia.FAMILIA, "", Tipografia.ETIQUETA_BARRA)
            self.set_text_color(*Paleta.ETIQUETA)
            self.set_xy(Medidas.MARGEN, y)
            self.cell(Medidas.BARRA_X - Medidas.MARGEN, Medidas.BARRA_ALTO,
                      sanear(etiqueta), align="L")

            self.set_fill_color(*Paleta.PISTA)
            self.rect(Medidas.BARRA_X, y, Medidas.BARRA_ANCHO,
                      Medidas.BARRA_ALTO, style="F")

            if mayor > 0 and valor > 0:
                ancho = Medidas.BARRA_ANCHO * valor / mayor
                self.set_fill_color(*color)
                self.rect(Medidas.BARRA_X, y, ancho, Medidas.BARRA_ALTO, style="F")

            self.set_font(Tipografia.FAMILIA, "B", Tipografia.ETIQUETA_BARRA)
            self.set_text_color(*Paleta.TEXTO)
            self.set_xy(Medidas.BARRA_X + Medidas.BARRA_ANCHO, y)
            self.cell(Medidas.ANCHO_UTIL + Medidas.MARGEN
                      - Medidas.BARRA_X - Medidas.BARRA_ANCHO,
                      Medidas.BARRA_ALTO, str(valor), align="C")

            self.set_xy(Medidas.MARGEN, y + Medidas.BARRA_SEPARACION)

        self.set_text_color(*Paleta.TEXTO)

    def tabla(self, encabezados: list[str], anchos: list[float],
              filas: list[list[Celda]], alineacion_encabezado=None):
        """
        Dibuja una tabla con cabecera azul y filas alternadas.

        El texto se envuelve en múltiples líneas si no cabe en la columna, para
        que los URLs, mensajes y errores sean legibles completos.
        """
        self._asegurar_espacio(Medidas.ENCABEZADO_ALTO + Medidas.FILA_ALTO * 2)
        self._dibujar_encabezado(encabezados, anchos, alineacion_encabezado)

        alterna = True
        for fila in filas:
            # Se mide primero cuántas líneas ocupa cada celda, porque la altura
            # de la fila es la de la celda más alta y hay que conocerla antes
            # de pintar el fondo.
            reparto = self._repartir_lineas(fila, anchos)
            alto_fila = max(
                Medidas.FILA_ALTO,
                max(len(lineas) for lineas in reparto) * Medidas.LINEA_TABLA
                + Medidas.SANGRIA_CELDA * 2,
            )

            if self.get_y() + alto_fila > self.page_break_trigger:
                self.add_page()
                self._dibujar_encabezado(encabezados, anchos, alineacion_encabezado)
                alterna = True

            fondo = Paleta.FILA_ALTERNA if alterna else Paleta.BLANCO
            alterna = not alterna

            y = self.get_y()

            # El fondo se pinta de una sola vez, con la altura ya calculada.
            self.set_fill_color(*fondo)
            self.rect(Medidas.MARGEN, y, sum(anchos), alto_fila, style="F")

            x = Medidas.MARGEN
            for celda, ancho, lineas in zip(fila, anchos, reparto):
                estilo = "B" if celda.negrita else ""
                self.set_font(Tipografia.FAMILIA, estilo, Tipografia.CUERPO_TABLA)
                self.set_text_color(*celda.color)

                # Las celdas de una sola línea se centran verticalmente en la
                # fila; las de varias arrancan arriba.
                if len(lineas) == 1:
                    inicio = y + (alto_fila - Medidas.LINEA_TABLA) / 2
                else:
                    inicio = y + Medidas.SANGRIA_CELDA

                for numero, texto in enumerate(lineas):
                    self.set_xy(x, inicio + numero * Medidas.LINEA_TABLA)
                    self.cell(ancho, Medidas.LINEA_TABLA, texto,
                              align=celda.alineacion)
                x += ancho

            self.set_xy(Medidas.MARGEN, y + alto_fila)

        self.set_text_color(*Paleta.TEXTO)

    def _dibujar_encabezado(self, encabezados, anchos, alineaciones=None):
        alineaciones = alineaciones or ["L"] * len(encabezados)
        x = Medidas.MARGEN
        y = self.get_y()
        self.set_font(Tipografia.FAMILIA, "B", Tipografia.ENCABEZADO_TABLA)
        for texto, ancho, alineacion in zip(encabezados, anchos, alineaciones):
            self.set_fill_color(*Paleta.NAVY)
            self.rect(x, y, ancho, Medidas.ENCABEZADO_ALTO, style="F")
            self.set_text_color(*Paleta.BLANCO)
            self.set_xy(x, y)
            self.cell(ancho, Medidas.ENCABEZADO_ALTO, sanear(texto), align=alineacion)
            x += ancho
        self.set_xy(Medidas.MARGEN, y + Medidas.ENCABEZADO_ALTO)
        self.set_text_color(*Paleta.TEXTO)

    # ------------------------------------------------------------------
    # Utilidades internas
    # ------------------------------------------------------------------

    def _repartir_lineas(self, fila: list[Celda],
                         anchos: list[float]) -> list[list[str]]:
        """Devuelve, para cada celda de la fila, las líneas que va a ocupar."""
        reparto = []
        for celda, ancho in zip(fila, anchos):
            # La medición depende del grosor de la letra, así que hay que fijar
            # la fuente de esta celda antes de medir.
            self.set_font(Tipografia.FAMILIA,
                          "B" if celda.negrita else "",
                          Tipografia.CUERPO_TABLA)
            reparto.append(
                self._envolver(celda.texto, ancho - 2 * Medidas.SANGRIA_CELDA))
        return reparto

    def _envolver(self, texto: str, ancho: float) -> list[str]:
        """
        Parte un texto en las líneas necesarias para que quepa en el ancho dado.

        Nada se recorta: el contenido se muestra completo. Se corta por espacios
        siempre que se pueda, y cuando una sola palabra no cabe, como pasa con
        un URL largo o con un secreto, se parte por caracteres.
        """
        if not texto:
            return [""]

        # La sangría de la celda va en el propio texto de varias columnas, así
        # que se conserva para que la primera línea siga alineada con el resto.
        margen_izquierdo = len(texto) - len(texto.lstrip())
        sangria = texto[:margen_izquierdo]

        lineas: list[str] = []
        actual = sangria

        for palabra in texto.strip().split(" "):
            if not palabra:
                continue
            tentativa = f"{actual} {palabra}" if actual.strip() else sangria + palabra

            if self.get_string_width(tentativa) <= ancho:
                actual = tentativa
                continue

            if actual.strip():
                lineas.append(actual)
                actual = sangria

            # La palabra sola tampoco cabe: se parte por caracteres.
            if self.get_string_width(sangria + palabra) > ancho:
                trozo = sangria
                for caracter in palabra:
                    if self.get_string_width(trozo + caracter) > ancho and trozo.strip():
                        lineas.append(trozo)
                        trozo = sangria + caracter
                    else:
                        trozo += caracter
                actual = trozo
            else:
                actual = sangria + palabra

        if actual.strip() or not lineas:
            lineas.append(actual)
        return lineas

    def _asegurar_espacio(self, alto: float):
        """Abre una página nueva si el bloque no cabe en lo que queda."""
        if self.get_y() + alto > self.page_break_trigger:
            self.add_page()
