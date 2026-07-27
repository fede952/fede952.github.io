---
title: "Publicado PoC de RCE en GitLab: Usuarios autenticados pueden ejecutar comandos como git"
date: "2026-07-27T10:37:15Z"
original_date: "2026-07-25T10:14:26"
lang: "es"
translationKey: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
slug: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
author: "NewsBot (Validated by Federico Sella)"
description: "Se publicó un exploit de prueba de concepto para una vulnerabilidad de ejecución remota de código en GitLab, dirigido a servidores autogestionados 18.11.3 sin parchear. Usuarios autenticados pueden ejecutar comandos como el usuario git."
original_url: "https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html"
source: "The Hacker News"
severity: "High"
target: "GitLab autogestionado 18.11.3"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Se publicó un exploit de prueba de concepto para una vulnerabilidad de ejecución remota de código en GitLab, dirigido a servidores autogestionados 18.11.3 sin parchear. Usuarios autenticados pueden ejecutar comandos como el usuario git.

{{< cyber-report severity="High" source="The Hacker News" target="GitLab autogestionado 18.11.3" >}}

El 24 de julio de 2026, investigadores de seguridad en depthfirst publicaron un exploit de prueba de concepto funcional para una vulnerabilidad de ejecución remota de código en GitLab. La falla, que GitLab parcheó el 10 de junio de 2026, permite a cualquier usuario autenticado con acceso de push a un proyecto ejecutar comandos arbitrarios como el usuario git en servidores GitLab autogestionados 18.11.3 que no hayan aplicado la actualización.

{{< ad-banner >}}

El exploit aprovecha un cuaderno Jupyter manipulado enviado a un proyecto. Cuando el atacante abre el diff del commit, el cuaderno malicioso desencadena una fuga de heap, permitiendo la ejecución de comandos. Esta técnica evita los controles de autenticación típicos y no requiere privilegios especiales más allá del acceso estándar al proyecto.

Las organizaciones que ejecutan instancias de GitLab autogestionadas deben verificar inmediatamente que hayan aplicado el parche del 10 de junio. La disponibilidad pública del código del exploit aumenta el riesgo de explotación activa, particularmente para instancias expuestas a internet. Los equipos azules deben monitorear commits inusuales de cuadernos Jupyter y actividad inesperada del usuario git.

{{< netrunner-insight >}}

Este exploit subraya el peligro de retrasar los parches en plataformas CI/CD autogestionadas. Los analistas del SOC deben priorizar la detección de procesos anómalos del usuario git y cargas inesperadas de cuadernos Jupyter. Los equipos DevSecOps deben imponer una ventana de parcheo estricta para GitLab y considerar la segmentación de red para limitar la exposición de las instancias autogestionadas.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)**
