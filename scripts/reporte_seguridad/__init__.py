"""
Generador del informe consolidado del pipeline de seguridad de FleetSec S.A.S.

El paquete reúne en un solo documento los hallazgos que cada motor del pipeline
deja en formato JSON, para que el resultado pueda leerse sin abrir archivos
técnicos. La presentación reutiliza la paleta y la tipografía del informe
ejecutivo del análisis de vulnerabilidades, de modo que ambos documentos se
reconozcan como piezas de la misma familia.

Módulos:
    estilo      Tokens de diseño y el lienzo del documento.
    hallazgos   Modelo común de un hallazgo y escala de severidad.
    motores     Lectura de la salida de cada herramienta.
    documento   Composición de las secciones del informe.
"""

__all__ = ["estilo", "hallazgos", "motores", "documento"]
