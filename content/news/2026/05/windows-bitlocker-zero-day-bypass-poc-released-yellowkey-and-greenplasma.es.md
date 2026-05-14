---
title: "PoC de bypass de día cero de Windows BitLocker publicado: YellowKey y GreenPlasma"
date: "2026-05-14T09:30:15Z"
original_date: "2026-05-13T16:37:49"
lang: "es"
translationKey: "windows-bitlocker-zero-day-bypass-poc-released-yellowkey-and-greenplasma"
author: "NewsBot (Validated by Federico Sella)"
description: "Se han publicado exploits de prueba de concepto para dos vulnerabilidades de Windows sin parchear: YellowKey (bypass de BitLocker) y GreenPlasma (escalada de privilegios), lo que supone riesgos para las unidades cifradas."
original_url: "https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/"
source: "BleepingComputer"
severity: "High"
target: "Unidades protegidas con BitLocker de Windows"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Se han publicado exploits de prueba de concepto para dos vulnerabilidades de Windows sin parchear: YellowKey (bypass de BitLocker) y GreenPlasma (escalada de privilegios), lo que supone riesgos para las unidades cifradas.

{{< cyber-report severity="High" source="BleepingComputer" target="Unidades protegidas con BitLocker de Windows" >}}

Un investigador de ciberseguridad ha publicado exploits de prueba de concepto (PoC) para dos vulnerabilidades de Microsoft Windows sin parchear, denominadas YellowKey y GreenPlasma. YellowKey es un bypass de BitLocker que permite a los atacantes acceder a datos en unidades protegidas sin la autenticación adecuada, mientras que GreenPlasma es una falla de escalada de privilegios que podría permitir a un atacante obtener permisos elevados en un sistema comprometido.

{{< ad-banner >}}

La publicación de estos PoC aumenta el riesgo de explotación, ya que los actores de amenazas ahora pueden convertir las técnicas en armas. Las organizaciones que dependen de BitLocker para el cifrado de disco completo deben evaluar su exposición y considerar controles de seguridad adicionales, como habilitar la protección TPM+PIN o usar autenticación previa al arranque.

Microsoft aún no ha lanzado parches para estas vulnerabilidades, dejando los sistemas expuestos hasta que se implementen las correcciones. Los equipos de seguridad deben monitorear patrones de acceso inusuales a las unidades cifradas y aplicar soluciones alternativas cuando sea posible, como deshabilitar opciones de arranque innecesarias o imponer políticas de PIN sólidas.

{{< netrunner-insight >}}

Para los analistas del SOC, priorice la monitorización de intentos no autorizados de acceder a unidades protegidas con BitLocker y eventos de escalada de privilegios. Los ingenieros de DevSecOps deben probar sus entornos contra los PoC publicados para identificar configuraciones vulnerables e implementar controles compensatorios como Secure Boot y registros de arranque medidos.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en BleepingComputer ›](https://www.bleepingcomputer.com/news/security/windows-bitlocker-zero-day-gives-access-to-protected-drives-poc-released/)**
