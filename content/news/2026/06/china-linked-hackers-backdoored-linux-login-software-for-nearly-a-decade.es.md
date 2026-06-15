---
title: "Hackers vinculados a China infectaron el software de inicio de sesión de Linux durante casi una década"
date: "2026-06-15T13:04:59Z"
original_date: "2026-06-12T18:17:55"
lang: "es"
translationKey: "china-linked-hackers-backdoored-linux-login-software-for-nearly-a-decade"
author: "NewsBot (Validated by Federico Sella)"
description: "Un grupo vinculado a China conocido como Velvet Ant comprometió componentes de PAM y OpenSSH, ocultándose en los sistemas de inicio de sesión de Linux durante casi diez años sin ser detectado."
original_url: "https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html"
source: "The Hacker News"
severity: "High"
target: "Sistemas de inicio de sesión de Linux (PAM, OpenSSH)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Un grupo vinculado a China conocido como Velvet Ant comprometió componentes de PAM y OpenSSH, ocultándose en los sistemas de inicio de sesión de Linux durante casi diez años sin ser detectado.

{{< cyber-report severity="High" source="The Hacker News" target="Sistemas de inicio de sesión de Linux (PAM, OpenSSH)" >}}

Se ha descubierto que un actor de amenazas vinculado a China, conocido como Velvet Ant, ha infectado componentes centrales de inicio de sesión de Linux, incluidos PAM (Módulos de Autenticación Conectables) y OpenSSH, lo que les permitió mantener acceso persistente durante casi una década. El grupo atacó una red donde incrustaron su puerta trasera profundamente en la pila de autenticación, haciéndola resistente a los procedimientos de limpieza estándar.

{{< ad-banner >}}

Según la firma de seguridad Sygnia, los atacantes explotaron la confianza depositada en el software de inicio de sesión para evadir la detección. Al modificar los mismos mecanismos que controlan el acceso de los usuarios, aseguraron que su punto de apoyo sobreviviera a las actualizaciones del sistema y a los escaneos de seguridad rutinarios. La campaña resalta la creciente sofisticación de los grupos patrocinados por estados al atacar infraestructuras fundamentales.

El compromiso subraya la necesidad de que las organizaciones monitoreen la integridad de los componentes críticos del sistema más allá de la detección típica de endpoints. Los defensores deberían considerar la monitorización de integridad de archivos para los módulos PAM y los binarios SSH, así como el análisis de comportamiento de los registros de autenticación para detectar anomalías indicativas de procesos de inicio de sesión infectados.

{{< netrunner-insight >}}

Para los analistas del SOC y los equipos de DevSecOps, esto es un claro recordatorio de que los atacantes están apuntando a la capa de autenticación misma. Implemente comprobaciones de integridad en tiempo de ejecución en los binarios de PAM y OpenSSH, y considere el uso de monitoreo a nivel de kernel para detectar manipulaciones. Además, revise los cambios en la autenticación basada en claves SSH y en la configuración de PAM como parte de sus manuales de respuesta a incidentes.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html)**
