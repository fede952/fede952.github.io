---
title: "Calculadora CVSS 4.0 (y CVSS 3.1)"
description: "Calcula la puntuación CVSS 4.0 con el método MacroVector oficial de FIRST, o las puntuaciones CVSS 3.1 base, temporal y de entorno. Pega un vector o haz clic."
intro: "Elige las métricas o pega una cadena de vector para obtener la puntuación **CVSS 4.0**, la gravedad, la nomenclatura (CVSS-B, BT, BE o BTE) y el MacroVector, calculados con **la lógica de puntuación y la tabla oficiales de FIRST**. Una segunda pestaña puntúa vectores **CVSS 3.1**, incluidas las puntuaciones temporal y de entorno. Comparte un resultado con un enlace `?vector=`. Todo se ejecuta en tu navegador."
date: 2026-10-26
lastmod: 2026-10-26
reviewed: false
keywords: ["calculadora cvss 4.0", "calculadora cvss", "calcular puntuación cvss", "calculadora cvss 3.1", "puntuación cvss vulnerabilidad", "vector cvss", "cvss 4 macrovector", "gravedad vulnerabilidad cvss"]
tags: ["security", "vulnerability", "cvss", "tool"]
app_category: "SecurityApplication"
tool_file: "/tools/cvss-calculator/"
tool_title: "Calculadora CVSS 4.0 y 3.1"
tool_height: 1400
tool_sandbox: "allow-scripts allow-same-origin"
tool_allow: "clipboard-write"
howto:
  - "Elige **CVSS 4.0** o **CVSS 3.1** con las pestañas."
  - "Pega una **cadena de vector** (por ejemplo, de un aviso de seguridad) o haz clic en el valor de cada métrica base."
  - "Si quieres, abre las métricas **de amenaza**, **de entorno** o, en 4.0, **suplementarias** para ajustar la puntuación a tu entorno."
  - "Lee la **puntuación**, la **gravedad** y, en 4.0, la **nomenclatura** que indica qué grupos de métricas se usaron."
  - "Pulsa **Copiar vector** para informes, o **Copiar enlace** para compartir una página que se abre con el mismo vector."
faq:
  - q: "¿La puntuación es la misma que la de la calculadora oficial de FIRST?"
    a: "Se calcula con el mismo método: el código CVSS 4.0 de esta herramienta es una adaptación de la función de puntuación de la calculadora oficial de FIRST y usa su tabla de MacroVectors sin cambios. Las pruebas verifican todos los vectores de ejemplo publicados en la página de ejemplos de CVSS 4.0 de FIRST y comparan 20 000 vectores aleatorios con el código oficial; CVSS 3.1 se compara igual con la calculadora 3.1 de FIRST. Este sitio no está afiliado a FIRST."
  - q: "¿Por qué CVSS 4.0 no usa una fórmula como la 3.1?"
    a: "CVSS 4.0 agrupa las métricas en seis conjuntos de equivalencia y asigna a cada combinación, un MacroVector, una puntuación fijada por expertos. La puntuación final parte de la del MacroVector y se ajusta según lo lejos que esté el vector del vector más grave del mismo MacroVector. Por eso la herramienta muestra el MacroVector junto a la puntuación."
  - q: "¿Qué significan CVSS-B, CVSS-BT, CVSS-BE y CVSS-BTE?"
    a: "Indican qué grupos de métricas incluye una puntuación CVSS 4.0: B solo Base, T añade las métricas de amenaza (madurez del exploit), E añade las de entorno. La puntuación base de un aviso es CVSS-B; al añadir información de exploits y tu propio entorno pasa a ser CVSS-BTE."
  - q: "¿Cuáles son los rangos de gravedad?"
    a: "La escala cualitativa es la misma en CVSS 3.1 y 4.0: Ninguna 0.0, Baja 0.1–3.9, Media 4.0–6.9, Alta 7.0–8.9, Crítica 9.0–10.0."
  - q: "¿Las métricas suplementarias cambian la puntuación?"
    a: "No. Safety, Automatable, Recovery, Value Density, Vulnerability Response Effort y Provider Urgency añaden contexto para decidir, pero no afectan a la puntuación CVSS 4.0. Siguen apareciendo en el vector."
  - q: "¿Se envía algo a un servidor?"
    a: "No. El cálculo se hace en tu navegador y la herramienta no hace peticiones de red. Un enlace compartido solo contiene la cadena de vector."
---

## Cómo funciona

### CVSS 4.0: MacroVectors y la tabla oficial

Las 11 métricas base, más la madurez del exploit y los requisitos de entorno, se reparten en seis grupos de equivalencia (EQ1–EQ6), como "qué tan accesible es el sistema" (vector de ataque, privilegios requeridos, interacción del usuario) o "qué tan grave es el impacto en el sistema vulnerable". El nivel de cada grupo forma un **MacroVector** de seis cifras, y la tabla de FIRST asigna una puntuación a cada uno de sus 270 valores posibles. La puntuación del vector es ese valor menos un ajuste según su distancia al vector más grave del mismo MacroVector, redondeada a un decimal. La implementación sigue paso a paso la calculadora oficial de FIRST y usa su tabla tal como se publica (licencia BSD-2-Clause, citada en el código).

### Métricas de entorno y de amenaza

Si no se indica, la **madurez del exploit** toma el peor caso (Attacked) y los requisitos de seguridad valen High, como dice la especificación. Las métricas **modificadas** sustituyen a la métrica base correspondiente en tu entorno: por ejemplo, un sistema accesible solo desde la red interna puede usar Modified Attack Vector: Adjacent.

### CVSS 3.1

La segunda pestaña aplica las ecuaciones de la especificación CVSS 3.1: la puntuación base a partir del impacto y la explotabilidad (con el ajuste por alcance), la temporal a partir de la madurez del código de exploit, el nivel de remediación y la confianza del informe, y la de entorno con las métricas modificadas y la función de redondeo de la 3.1.

## Casos de uso

- **Clasificar avisos** — pega el vector de un registro CVE o de un boletín del fabricante y mira qué determina la puntuación.
- **Puntuar tus hallazgos** — para un informe de pruebas de penetración o un envío de bug bounty, con un vector que otros pueden verificar.
- **Adaptar a tu entorno** — usa las métricas de entorno para clasificar distinto la misma vulnerabilidad en sistemas expuestos a internet e internos.
- **Comparar 3.1 y 4.0** — muchas bases de datos publican aún ambas; puntúa el mismo problema en cada pestaña.
- **Aprender las métricas** — cada valor tiene su etiqueta y la puntuación se actualiza con cada clic.
