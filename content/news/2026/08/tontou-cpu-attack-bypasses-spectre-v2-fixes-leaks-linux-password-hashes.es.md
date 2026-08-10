---
title: "El ataque TONTOU a la CPU evita las correcciones de Spectre v2 y filtra hashes de contraseñas de Linux"
date: "2026-08-10T08:26:15Z"
original_date: "2026-08-06T18:03:45"
lang: "es"
translationKey: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
slug: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "Investigadores desarrollan el ataque TONTOU que evita las mitigaciones recientes de Spectre v2, logrando filtrar secretos, incluidos hashes de contraseñas, de sistemas Linux."
original_url: "https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/"
source: "BleepingComputer"
severity: "High"
target: "sistemas Linux"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Investigadores desarrollan el ataque TONTOU que evita las mitigaciones recientes de Spectre v2, logrando filtrar secretos, incluidos hashes de contraseñas, de sistemas Linux.

{{< cyber-report severity="High" source="BleepingComputer" target="sistemas Linux" >}}

Investigadores de seguridad han revelado un nuevo ataque de ejecución especulativa, denominado TONTOU, que elude las mitigaciones recientes para la vulnerabilidad Spectre v2. El ataque se dirige a los mecanismos de predicción de ramas de la CPU, que fueron parcheados previamente para prevenir fugas por canales laterales. Al explotar una brecha en estas defensas, los investigadores pudieron extraer datos sensibles de la memoria del kernel de máquinas Linux.

{{< ad-banner >}}

La prueba de concepto demuestra la gravedad del problema al filtrar con éxito hashes de contraseñas del sistema objetivo. Esto indica que el ataque podría utilizarse para comprometer credenciales de usuario y potencialmente escalar privilegios. Los hallazgos resaltan el desafío continuo de mitigar por completo los ataques de ejecución especulativa por canal lateral, ya que siguen surgiendo nuevas variantes a pesar de las correcciones anteriores.

Si bien los investigadores aún no han publicado todos los detalles técnicos, su trabajo subraya la necesidad de mantener una vigilancia continua en la seguridad de la CPU. Se recomienda a los administradores de sistemas que estén atentos a las actualizaciones de los proveedores de CPU y de las distribuciones de Linux, y que consideren medidas de endurecimiento adicionales como la aleatorización del diseño del espacio de direcciones del kernel (KASLR) y las actualizaciones de microcódigo.

{{< netrunner-insight >}}

Este ataque es un recordatorio contundente de que las vulnerabilidades de ejecución especulativa no están completamente resueltas. Los analistas del SOC deben priorizar los parches y monitorear cualquier indicador de explotación, mientras que los ingenieros de DevSecOps deben revisar sus modelos de amenazas para detectar riesgos de canal lateral. Dado el potencial de filtrar hashes de contraseñas, se justifica una atención inmediata a las actualizaciones del kernel de Linux y al microcódigo de la CPU.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en BleepingComputer ›](https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/)**
