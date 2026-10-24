---
title: "Aim Trainer y Test de Reflejos Online"
description: "Entrena tu puntería con el ratón en sesiones de 60 segundos: haz clic en dianas luminosas y obtén aciertos, precisión, tiempo de reacción y un rango."
intro: "**ReflexGrid** es un aim trainer de 60 segundos: las dianas aparecen en cualquier punto de la cuadrícula, las pulsas o tocas lo más rápido posible y al final obtienes aciertos, precisión, tiempo medio hasta la diana y un rango de *Potato* a *Pro*."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["aim trainer", "test de reflejos", "test de tiempo de reacción", "entrenar puntería", "test de precisión del ratón", "aim trainer online", "entrenamiento fps", "test de velocidad de clic"]
tags: ["juegos", "gaming", "reflejos", "herramienta"]
app_category: "GameApplication"
tool_file: "/tools/reflex-grid/"
tool_title: "ReflexGrid, entrenador de puntería"
tool_height: 760
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Pulsa **Start Training**. Empieza el temporizador de 60 segundos y aparece la primera diana."
  - "Haz clic (o toca en pantallas táctiles) cada círculo luminoso lo más rápido y preciso que puedas. En cuanto aciertas aparece otro."
  - "Vigila la barra superior: tiempo restante, aciertos y precisión en directo. Los clics fallados bajan tu precisión."
  - "Cuando se acaba el tiempo, lee los resultados: **Targets Hit**, **Accuracy**, **Avg Reaction** y **Total Clicks**, además de tu rango."
  - "Pulsa **Play Again** para superar tu marca. Calienta con unas cuantas rondas antes de comparar resultados."
faq:
  - q: "¿Qué es un buen tiempo de reacción en este test?"
    a: "La media aquí es el tiempo desde que aparece la diana hasta que aciertas, así que incluye mover el ratón y no solo reaccionar. Por debajo de 300 ms (rango *Gamer*) es bueno; por debajo de 200 ms (*Pro*), excelente. El tiempo de reacción visual simple de un adulto ronda los 200–250 ms, así que las cifras de ReflexGrid son lógicamente algo más altas."
  - q: "¿Cómo se calculan los rangos?"
    a: "A partir del tiempo medio hasta la diana: menos de 200 ms es *Pro*, menos de 300 ms *Gamer*, menos de 400 ms *Casual*, menos de 500 ms *Novice* y cualquier cosa más lenta *Potato*. La precisión se muestra aparte; para progresar de verdad, mantenla por encima del 80 % mientras bajas el tiempo."
  - q: "¿Importan la sensibilidad o los DPI del ratón?"
    a: "Sí, muchísimo. Entrenar la puntería solo sirve con la misma sensibilidad con la que juegas, así que mantén tus DPI y los ajustes del puntero. Desactivar \"mejorar la precisión del puntero\" (la aceleración) en Windows hace los movimientos más constantes y fáciles de entrenar."
  - q: "¿Por qué algunas dianas son rojas?"
    a: "Alrededor del 40 % de las dianas son rojas en lugar de cian, solo como variación visual para que no anticipes. Todas cuentan igual."
  - q: "¿Se puede jugar en el móvil?"
    a: "Sí. El canvas escucha eventos táctiles además del ratón, así que los toques cuentan como clics. Los tiempos táctiles no son comparables con los del ratón: compárate contigo mismo en el mismo dispositivo."
  - q: "¿Se guardan o se envían mis puntuaciones?"
    a: "No. Cada sesión vive solo en la página; no se guarda ni se envía nada. Apunta tu mejor resultado si quieres seguir tu progreso."
---

## Cómo funciona

El juego se dibuja en un `<canvas>` HTML escalado a la densidad de píxeles de tu pantalla, con una cuadrícula de fondo animada y una barra HUD arriba.

**Dianas.** Cada diana recibe un radio aleatorio de entre 20 y 35 píxeles y una posición aleatoria, separada de los bordes y del HUD. Pulsa un ±12 % para que nunca esté del todo quieta. El momento en que aparece se guarda con `performance.now()`, el reloj de alta resolución del navegador.

**Aciertos y fallos.** En cada `mousedown` o `touchstart` se calcula con Pitágoras la distancia del puntero al centro de la diana. Todo lo que queda dentro de 1,3 veces el radio cuenta como acierto, un pequeño margen por el brillo y la pulsación. Un acierto registra el tiempo de reacción (ahora − momento de aparición), reproduce un tono corto de onda cuadrada ascendente generado con la Web Audio API, lanza una ráfaga de partículas y hace aparecer al instante la siguiente diana. Un fallo reproduce un tono de diente de sierra descendente y solo aumenta tu número de clics.

**Puntuación.** Al terminar los 60 segundos:

- **Targets Hit** es el número de clics acertados;
- **Accuracy** es aciertos ÷ clics totales;
- **Avg Reaction** es la media de todos los tiempos de reacción registrados, en milisegundos;
- el **rango** depende de esa media.

| Tiempo medio hasta la diana | Rango |
|---|---|
| menos de 200 ms | Pro |
| 200–299 ms | Gamer |
| 300–399 ms | Casual |
| 400–499 ms | Novice |
| 500 ms o más | Potato |

Como cada diana aparece en el mismo instante en que aciertas la anterior, el test mide la velocidad de *flick*: ver una diana nueva, ir hasta ella y hacer clic. Se parece más a lo que exigen los FPS que un test de "espera a que la pantalla se ponga verde".

## Casos de uso

- **Calentar antes de jugar a FPS** como Valorant, CS2, Apex Legends u Overwatch: dos o tres rondas sincronizan mano y vista.
- **Probar un ratón o una sensibilidad nuevos.** Juega unas rondas con cada ajuste y compara precisión y tiempo hasta la diana.
- **Seguir tu mejora.** Apunta media y precisión cada día; la práctica constante se nota en tiempos más bajos con la misma precisión.
- **Un descanso rápido.** Un minuto de clics concentrados es un buen reinicio entre sesiones largas de trabajo.
- **Ergonomía.** Una caída brusca de precisión puede ser señal de cansancio; tómate un respiro.
