---
title: "Temporizador de Enfoque y Ruido Blanco"
description: "Mezcla ruido blanco, rosa y marrón, lluvia, chimenea, teclado y cafetería, y usa un temporizador Pomodoro. Sonidos generados en vivo en tu navegador."
intro: "**ZenFocus** combina un temporizador de concentración con un mezclador de sonido ambiental de ocho canales. Elige un preset o crea tu propia mezcla de ruido, lluvia, chimenea, teclas y murmullo de cafetería, y empieza una sesión de 25 minutos. Cada sonido se genera en vivo en tu navegador: sin archivos de audio ni cuenta."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["temporizador de concentración", "temporizador pomodoro online", "mezclador de sonidos ambientales", "ruido marrón", "ruido blanco online", "ruido rosa", "sonido de lluvia para estudiar", "ruido de fondo para concentrarse"]
tags: ["productividad", "concentración", "audio", "herramienta"]
app_category: "UtilitiesApplication"
tool_file: "/tools/zen-focus/"
tool_title: "ZenFocus, temporizador y mezclador de ruido"
tool_height: 800
tool_sandbox: "allow-scripts allow-same-origin allow-popups allow-popups-to-escape-sandbox"
tool_allow: "clipboard-write; web-share"
howto:
  - "Elige un preset: **Deep Work** (ruido marrón y lluvia), **Coffee Break** (murmullo de cafetería y chimenea) o **Silence** para silenciar todos los canales."
  - "O crea tu mezcla moviendo el deslizador de cada tarjeta. El botón 🔊 de una tarjeta silencia ese canal sin perder su nivel."
  - "Ajusta el volumen general con el deslizador **Master**. Empieza bajo: el ruido de enmascaramiento funciona mejor cuando apenas cubre las distracciones."
  - "Ajusta la duración con **−5**, **−1**, **+1** y **+5** (de 1 a 90 minutos, 25 por defecto) y pulsa **Start**."
  - "Trabaja hasta que suene la campanilla. **Pause** detiene el reloj y **Reset** restaura la duración completa. Para un descanso, pon 5 minutos y vuelve a empezar."
faq:
  - q: "¿Qué diferencia hay entre el ruido blanco, rosa y marrón?"
    a: "Cambia cómo se reparte la energía entre las frecuencias. El ruido blanco tiene la misma potencia en todas y suena siseante. El rosa pierde unos 3 dB por octava, así que es más suave, parecido a una lluvia constante. El marrón (browniano) pierde unos 6 dB por octava y suena como un retumbar profundo o una cascada lejana. Mucha gente encuentra el rosa y el marrón menos cansados que el blanco en sesiones largas."
  - q: "¿El ruido de fondo mejora de verdad la concentración?"
    a: "La evidencia es mixta. Un ruido constante enmascara de forma fiable los sonidos impredecibles, como voces y notificaciones, que son los que suelen romper la concentración. Algunos estudios observan beneficios para la atención, sobre todo en personas con TDAH; otros no encuentran efecto o ven un coste en la lectura compleja. Tómalo como un experimento personal: prueba una mezcla una semana y quédate con ella si te ayuda."
  - q: "¿Qué es la técnica Pomodoro?"
    a: "Un método de gestión del tiempo creado por Francesco Cirillo: trabajas en una tarea 25 minutos, descansas 5 y, tras cuatro rondas, haces un descanso más largo de 15–30 minutos. ZenFocus empieza en 25 minutos; para los descansos pon 5. No cambia automáticamente, así que tú decides cuándo empieza la siguiente ronda."
  - q: "¿El temporizador sigue en una pestaña en segundo plano?"
    a: "Sí. La cuenta atrás se calcula a partir de una hora de fin fija y no contando ticks, así que sigue siendo precisa aunque el navegador ralentice los temporizadores de pestañas ocultas. La campanilla suena al terminar, siempre que la pestaña siga abierta."
  - q: "¿Por qué no suena nada hasta que hago clic?"
    a: "Los navegadores bloquean el audio hasta que interactúas con la página. ZenFocus arranca su motor de audio con tu primer clic en un deslizador, un preset o Start, y luego sube los canales suavemente."
  - q: "¿Los sonidos son grabaciones?"
    a: "No. Cada canal se sintetiza con la Web Audio API: búferes de ruido modelados con filtros (la lluvia, por ejemplo, es ruido blanco con paso alto y el trueno ruido marrón con paso bajo), y el teclado es una serie de clics cortos aleatorios. No se descarga ni se transmite nada, así que también funciona sin conexión una vez cargada la página."
  - q: "¿Es seguro escuchar durante horas?"
    a: "Mantén un volumen moderado. Una pauta habitual es quedarse en un nivel en el que aún oigas a alguien que te habla al lado y hacer pausas regulares. La exposición prolongada a sonido fuerte con auriculares puede dañar el oído."
---

## Cómo funciona

ZenFocus es una sola página basada en la **Web Audio API**. En tu primera interacción crea un `AudioContext` y genera en memoria unos segundos de ruido en bruto:

- **Ruido blanco**: muestras aleatorias uniformes entre −1 y 1, lo que da un espectro plano.
- **Ruido rosa**: el conocido filtro de Paul Kellet, un banco de filtros de primer orden que aproxima una pendiente de −3 dB/octava.
- **Ruido marrón**: un "integrador con fugas" que acumula pasos aleatorios, con pendiente de −6 dB/octava.
- **Clics de teclado**: unos cinco impulsos breves por segundo, con caída exponencial y volumen aleatorio.

Los búferes rosa y marrón se ajustan para que su última muestra coincida con la primera, de modo que el punto de bucle no hace clic. Cada uno de los ocho canales es una fuente en bucle, opcionalmente filtrada por un biquad, seguida de un nodo de ganancia (el deslizador de la tarjeta) y de la ganancia master:

| Canal | Fuente | Filtro |
|---|---|---|
| White Noise | blanco | ninguno |
| Pink Noise | rosa | ninguno |
| Brown Noise | marrón | ninguno |
| Rain | blanco | paso alto 1,2 kHz |
| Thunder | marrón | paso bajo 100 Hz |
| Fireplace | blanco | paso banda 700 Hz |
| Keyboard | clics | paso banda 2,2 kHz |
| Coffee Shop | rosa | paso banda ancho 1 kHz |

Todos los canales suenan desde el principio; mover un deslizador solo cambia su ganancia, con una rampa de 50 ms para que nunca haya chasquidos. Silenciar lleva la ganancia a cero pero recuerda el valor del deslizador.

**El temporizador** guarda el instante en que debe terminar la sesión y recalcula el tiempo restante cuatro veces por segundo. Los navegadores pueden ralentizar `setInterval` en pestañas en segundo plano, pero como la pantalla se deriva del reloj y no de ticks contados, una sesión de 25 minutos termina a los 25 minutos. Al llegar a cero suenan tres tonos senoidales (un arpegio de La mayor: 880, 1109 y 1319 Hz) como una campanilla suave.

El botón Share usa el panel de compartir nativo del dispositivo si existe y, si no, copia el enlace de la página. Nada más sale de la página: no se guardan ajustes ni uso.

## Casos de uso

- **Bloques de trabajo profundo.** Activa Deep Work, pon 50 minutos y cierra todo lo demás: el retumbar constante tapa la charla de la oficina y el ruido de la calle.
- **Estudiar con el método Pomodoro.** Alterna sesiones de 25 minutos y descansos de 5, con uno más largo tras cuatro rondas.
- **Oficinas abiertas y pisos compartidos.** Ruido rosa o marrón con auriculares a bajo volumen cubre el habla inteligible, el sonido que más distrae a la mayoría.
- **Escribir y leer.** Una mezcla suave de Coffee Shop + Fireplace crea ambiente de cafetería sin letras de canciones que compitan por tu atención.
- **Desconectar.** Lluvia y ruido marrón son un fondo tranquilo para leer antes de dormir; usa el temporizador para dejar el móvil.
- **Poner tiempo a tareas y reuniones.** Pon 10 o 15 minutos para esa tarea que siempre aplazas: la campanilla te avisa de cuándo parar.
