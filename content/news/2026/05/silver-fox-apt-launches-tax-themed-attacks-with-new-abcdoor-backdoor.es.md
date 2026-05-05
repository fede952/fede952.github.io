---
title: "Silver Fox APT lanza ataques con temática fiscal utilizando el nuevo backdoor ABCDoor"
date: "2026-05-05T09:10:11Z"
original_date: "2026-05-04T14:39:26"
lang: "es"
translationKey: "silver-fox-apt-launches-tax-themed-attacks-with-new-abcdoor-backdoor"
author: "NewsBot (Validated by Federico Sella)"
description: "Silver Fox, respaldado por China, ataca India y Rusia con phishing de temática fiscal, desplegando el backdoor ABCDoor y el malware ValleyRAT."
original_url: "https://www.darkreading.com/endpoint-security/silver-fox-tax-themed-attacks-india-russia"
source: "Dark Reading"
severity: "High"
target: "Organizaciones en India y Rusia"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Silver Fox, respaldado por China, ataca India y Rusia con phishing de temática fiscal, desplegando el backdoor ABCDoor y el malware ValleyRAT.

{{< cyber-report severity="High" source="Dark Reading" target="Organizaciones en India y Rusia" >}}

El grupo de amenaza persistente avanzada respaldado por China conocido como Silver Fox ha lanzado una nueva campaña utilizando ingeniería social con temática fiscal para atacar organizaciones en India y Rusia. Los ataques involucran más de 1.600 mensajes de ingeniería social dirigidos a diversos sectores, entregando malware previamente no documentado, incluido el backdoor ABCDoor y ValleyRAT.

{{< ad-banner >}}

El backdoor ABCDoor es una nueva adición al arsenal de Silver Fox, diseñado para establecer acceso persistente y exfiltrar datos. ValleyRAT, un troyano de acceso remoto conocido, también se despliega en estos ataques. La campaña destaca el enfoque continuo del grupo en entidades financieras y gubernamentales, aprovechando temas fiscales oportunos para aumentar la participación de las víctimas.

Los investigadores de seguridad instan a las organizaciones en las regiones afectadas a mejorar el filtrado de correo electrónico y la capacitación en concienciación de usuarios, ya que los ataques dependen en gran medida de la ingeniería social. Se deben monitorear los indicadores de compromiso (IOC) asociados con la campaña y actualizar las defensas de red para detectar el nuevo backdoor y RAT.

{{< netrunner-insight >}}

Los analistas del SOC deben priorizar la monitorización de correos electrónicos de phishing con temática fiscal e implementar reglas de detección de comportamiento para las firmas de red del backdoor ABCDoor. Los equipos de DevSecOps deben asegurarse de que las herramientas de detección y respuesta en endpoints (EDR) estén ajustadas para identificar los mecanismos de persistencia de ValleyRAT, y considerar bloquear la infraestructura C2 conocida asociada con Silver Fox.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en Dark Reading ›](https://www.darkreading.com/endpoint-security/silver-fox-tax-themed-attacks-india-russia)**
