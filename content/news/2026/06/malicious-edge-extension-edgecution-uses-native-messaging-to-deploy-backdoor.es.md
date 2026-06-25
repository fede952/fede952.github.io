---
title: "Extensión maliciosa de Edge 'Edgecution' usa mensajería nativa para implementar puerta trasera"
date: "2026-06-25T10:16:09Z"
original_date: "2026-06-24T20:58:22"
lang: "es"
translationKey: "malicious-edge-extension-edgecution-uses-native-messaging-to-deploy-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "Una extensión maliciosa de Microsoft Edge llamada 'Edgecution' escapa del sandbox del navegador mediante la mensajería nativa para implementar una puerta trasera basada en Python en ataques de ransomware."
original_url: "https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/"
source: "BleepingComputer"
severity: "High"
target: "Usuarios de Microsoft Edge"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Una extensión maliciosa de Microsoft Edge llamada 'Edgecution' escapa del sandbox del navegador mediante la mensajería nativa para implementar una puerta trasera basada en Python en ataques de ransomware.

{{< cyber-report severity="High" source="BleepingComputer" target="Usuarios de Microsoft Edge" >}}

Se ha observado una extensión maliciosa de Microsoft Edge apodada 'Edgecution' en un ataque de ransomware, aprovechando la API de mensajería nativa del navegador para escapar del sandbox y ejecutar código arbitrario en el sistema anfitrión. La extensión actúa como un puente para implementar una puerta trasera basada en Python, permitiendo acceso persistente y actividades maliciosas adicionales.

{{< ad-banner >}}

La cadena de ataque comienza con la instalación de la extensión maliciosa, que luego abusa de la mensajería nativa para comunicarse con una aplicación nativa fuera del sandbox del navegador. Esta técnica evita los límites de seguridad típicos del navegador, permitiendo al atacante ejecutar comandos y soltar cargas útiles adicionales, incluido el ransomware.

Los investigadores de seguridad destacan que este método es particularmente insidioso porque explota una característica legítima del navegador, lo que dificulta la detección por parte de las soluciones de seguridad tradicionales de endpoints. Se recomienda a las organizaciones monitorear las extensiones de navegador no autorizadas y restringir los permisos de mensajería nativa cuando sea posible.

{{< netrunner-insight >}}

Este ataque subraya la importancia de monitorear las instalaciones de extensiones del navegador y la actividad de mensajería nativa. Los analistas del SOC deben buscar comportamientos anómalos de extensiones y comunicaciones inesperadas con hosts nativos, mientras que los equipos de DevSecOps deben aplicar listas blancas estrictas de extensiones y deshabilitar hosts de mensajería nativa innecesarios.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en BleepingComputer ›](https://www.bleepingcomputer.com/news/security/malicious-edge-extension-abuses-native-messaging-as-bridge-to-malware/)**
