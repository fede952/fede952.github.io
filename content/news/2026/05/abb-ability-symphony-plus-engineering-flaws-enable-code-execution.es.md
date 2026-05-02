---
title: "Fallos en ABB Ability Symphony Plus Engineering permiten ejecución de código"
date: "2026-05-02T08:20:38Z"
original_date: "2026-04-30T12:00:00"
lang: "es"
translationKey: "abb-ability-symphony-plus-engineering-flaws-enable-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA advierte sobre vulnerabilidades en ABB Ability Symphony Plus Engineering debido a PostgreSQL desactualizado, lo que permite ejecución de código arbitrario en sistemas afectados."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06"
source: "CISA"
severity: "High"
target: "ABB Ability Symphony Plus Engineering"
cve: "CVE-2023-5869"
cvss: 8.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA advierte sobre vulnerabilidades en ABB Ability Symphony Plus Engineering debido a PostgreSQL desactualizado, lo que permite ejecución de código arbitrario en sistemas afectados.

{{< cyber-report severity="High" source="CISA" target="ABB Ability Symphony Plus Engineering" cve="CVE-2023-5869" cvss="8.8" >}}

CISA ha publicado un aviso (ICSA-26-120-06) que detalla múltiples vulnerabilidades en ABB Ability Symphony Plus Engineering, derivadas del uso de PostgreSQL versión 13.11 y anteriores. Las fallas incluyen desbordamiento de enteros, inyección SQL, condición de carrera TOCTOU y errores de eliminación de privilegios, que podrían permitir a un atacante autenticado ejecutar código arbitrario en el sistema.

{{< ad-banner >}}

Las versiones afectadas abarcan desde Ability Symphony Plus 2.2 hasta 2.4 SP2 RU1. Las vulnerabilidades son particularmente preocupantes dado el despliegue del producto en sectores de infraestructura crítica como Químico, Manufactura Crítica, Energía y Agua y Aguas Residuales a nivel mundial.

La vulnerabilidad más notable, CVE-2023-5869, tiene una puntuación CVSS de 8.8 e implica un desbordamiento de enteros que puede ser desencadenado por datos manipulados de un usuario autenticado de PostgreSQL. Una explotación exitosa podría llevar al compromiso total del sistema, enfatizando la necesidad de parcheo inmediato.

{{< netrunner-insight >}}

Este aviso subraya el riesgo de dependencias desactualizadas en entornos OT. Los analistas del SOC deben priorizar el descubrimiento de activos para instancias de ABB Symphony Plus y asegurarse de que PostgreSQL esté actualizado más allá de la versión 13.11. Los equipos de DevSecOps deben integrar el escaneo de dependencias en los pipelines de CI/CD para sistemas de control industrial a fin de detectar estas vulnerabilidades heredadas de manera temprana.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-120-06)**
