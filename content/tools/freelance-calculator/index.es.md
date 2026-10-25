---
title: "Calculadora de Tarifa por Hora Freelance"
description: "Calcula la tarifa por hora y por día que necesitas como freelance a partir del neto deseado, días y horas facturables, impuestos y gastos. Gratis."
intro: "**RateMate** convierte los ingresos que quieres llevarte a casa en la tarifa que necesitas cobrar. Introduce el salario neto anual deseado, los días y horas facturables, el tipo impositivo y los gastos mensuales, y obtén al instante tu tarifa por hora, tu tarifa diaria y lo que debes facturar al mes."
date: 2026-02-03
lastmod: 2026-10-24
reviewed: false
keywords: ["calculadora tarifa freelance", "cuánto cobrar como freelance", "calcular precio por hora autónomo", "calculadora tarifa diaria", "tarifa consultor", "precio freelance", "tarifa por hora autónomo", "calcular honorarios"]
tags: ["freelance", "finanzas", "negocio", "herramienta"]
app_category: "FinanceApplication"
tool_file: "/tools/freelance-calculator/"
tool_title: "RateMate, calculadora de tarifa freelance"
tool_height: 900
tool_sandbox: "allow-scripts allow-same-origin"
howto:
  - "Elige la moneda ($, € o £) e introduce el **Desired Annual Net Salary**: lo que quieres conservar después de impuestos y gastos del negocio."
  - "Ajusta **Billable Days per Year**. El valor por defecto es 220; descuenta con honestidad vacaciones, bajas, administración y tiempo comercial."
  - "Ajusta **Daily Billable Hours**: las horas que de verdad puedes facturar, normalmente 5–7 y no 8."
  - "Mueve el control **Tax Rate** a tu tipo efectivo de impuestos y cotizaciones, e introduce tus **Monthly Expenses** (software, equipo, seguros, coworking, gestoría)."
  - "Lee **Your Hourly Rate**, el **Daily Rate** y el **Monthly Gross** que tienes que facturar. El gráfico de anillo muestra cómo se reparte cada euro facturado entre ingresos, impuestos y gastos."
faq:
  - q: "¿Cómo calculo mi tarifa por hora como freelance?"
    a: "Parte de los ingresos que necesitas, no de lo que cobran otros. Suma tus gastos anuales del negocio, eleva el total para cubrir impuestos y divide entre las horas que puedes facturar de forma realista. Con los valores por defecto (60.000 netos, 500 al mes de gastos, 25 % de impuestos, 220 días de 6 horas facturables) sale (60.000 + 6.000) ÷ 0,75 = 88.000 al año, 400 al día, unos 67 la hora."
  - q: "¿Cuántos días facturables al año debo contar?"
    a: "Un año tiene unos 260 días laborables. Resta los festivos (8–14 según el país), 20–25 días de vacaciones, algunos días de baja y el tiempo de ventas, administración y formación. La mayoría de freelancers acaba entre 180 y 220 días facturables; quien empieza y aún no tiene clientes estables suele facturar menos."
  - q: "¿Por qué las horas facturables son menos que las trabajadas?"
    a: "Correos, facturas, presupuestos, reuniones que no se cobran y cambios de contexto se llevan su tiempo. Seis horas facturables en una jornada de ocho es una cifra habitual y sostenible. Si facturas ocho horas cada día, probablemente trabajas diez."
  - q: "¿Qué tipo impositivo debo poner?"
    a: "Tu tipo *efectivo*: impuestos más cotizaciones sociales divididos entre la facturación bruta, no tu tramo marginal más alto. Varía mucho según el país y el régimen (en España, por ejemplo, entre IRPF y cuota de autónomos); para una primera estimación usa las cifras del año pasado o pregunta a tu asesor, y prueba varios valores para ver cuánto cambia la tarifa."
  - q: "¿La calculadora trata los gastos como deducibles?"
    a: "No. Aplica el tipo impositivo a todo el bruto, gastos incluidos, lo que da una tarifa algo más alta y prudente. Si los gastos son totalmente deducibles, el bruto necesario es neto ÷ (1 − tipo) + gastos: con los valores por defecto, 86.000 en lugar de 88.000, unos 65 la hora en vez de 67."
  - q: "¿Cobrar por hora, por día o por proyecto?"
    a: "Usa la cifra por hora como suelo. Muchos freelancers presupuestan por día (lo verás aquí) o con un precio cerrado por proyecto calculado a partir de ella, que premia la eficiencia y no las horas. Presupuestes como presupuestes, comprueba que nunca quede por debajo de la tarifa por hora de esta calculadora."
  - q: "¿Se guardan mis datos económicos?"
    a: "No. El cálculo se hace en tu navegador y no se guarda ni se envía nada. Cierra la página y los números desaparecen."
---

## Cómo funciona

RateMate trabaja hacia atrás, a partir del dinero que quieres conservar.

1. **Gastos anuales** = gastos mensuales × 12.
2. **Bruto anual necesario** = (neto deseado + gastos anuales) ÷ (1 − tipo impositivo).
   El tipo se trata como una parte fija de todo lo que facturas, así que la fórmula eleva tanto tu salario como tus costes.
3. **Impuestos anuales** = bruto − neto − gastos.
4. **Tarifa diaria** = bruto ÷ días facturables.
5. **Tarifa por hora** = tarifa diaria ÷ horas facturables por día.
6. **Bruto mensual** = bruto ÷ 12, lo que necesitas facturar de media cada mes.

El gráfico de anillo, dibujado con Chart.js, muestra las tres partes del bruto: ingresos netos, impuestos y gastos. Cada campo recalcula al escribir, así que puedes arrastrar el control de impuestos (0–60 %) y ver cómo se mueve la tarifa.

### Ejemplo práctico

| Dato | Valor |
|---|---|
| Neto deseado | 60.000 |
| Gastos mensuales | 500 (6.000 al año) |
| Tipo impositivo | 25 % |
| Días facturables | 220 |
| Horas facturables por día | 6 |

Bruto = 66.000 ÷ 0,75 = **88.000** al año → **400** al día → **≈ 67** la hora → **≈ 7.333** a facturar al mes. De cada 100 facturados, unos 68 son ingresos, 25 impuestos y 7 cubren gastos.

Cambia una sola hipótesis y entenderás por qué las tarifas varían tanto. Con 180 días facturables la tarifa por hora sube a unos 81; con 5 horas facturables al día en lugar de 6, a 80. La palanca más fuerte no suele ser el tipo impositivo, sino cuánto de tu tiempo puedes facturar de verdad.

### Lo que el modelo no incluye

La calculadora se limita a propósito a un único tipo efectivo. No modela tramos progresivos, el IVA (que se suma a tu tarifa y se ingresa a Hacienda), aportaciones a planes de pensiones más allá de lo que incluyas en el "neto" ni los huecos sin cobrar entre contratos. Si te afectan, añade un margen o sube la cifra neta.

## Casos de uso

- **Hacerte freelance.** Convierte tu salario de asalariado en la tarifa que necesitas y entiende enseguida por qué un freelance debe cobrar mucho más que salario ÷ 2.080 horas.
- **Preparar un presupuesto.** Comprueba que el precio de un proyecto, dividido entre los días que llevará, queda por encima de tu tarifa diaria.
- **Subir tus tarifas.** Mete los gastos y el tipo impositivo reales de este año y mira si tu tarifa actual todavía los cubre.
- **Comparar ofertas.** Compara la tarifa diaria de un contrato con un salario fijo en igualdad de condiciones.
- **Planificar un año sabático o una formación.** Reduce los días facturables y mira cuánto debe subir la tarifa para mantener los mismos ingresos.
