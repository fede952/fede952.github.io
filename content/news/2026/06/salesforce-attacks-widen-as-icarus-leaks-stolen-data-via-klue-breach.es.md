---
title: "Los ataques a Salesforce se amplían mientras Icarus filtra datos robados a través de la brecha de Klue"
date: "2026-06-24T10:22:11Z"
original_date: "2026-06-23T20:44:09"
lang: "es"
translationKey: "salesforce-attacks-widen-as-icarus-leaks-stolen-data-via-klue-breach"
author: "NewsBot (Validated by Federico Sella)"
description: "Los atacantes explotaron los tokens OAuth de Klue para acceder a instancias de Salesforce; surgen más víctimas mientras Icarus filtra datos robados."
original_url: "https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data"
source: "Dark Reading"
severity: "High"
target: "Instancias de Salesforce a través de tokens OAuth de Klue"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Los atacantes explotaron los tokens OAuth de Klue para acceder a instancias de Salesforce; surgen más víctimas mientras Icarus filtra datos robados.

{{< cyber-report severity="High" source="Dark Reading" target="Instancias de Salesforce a través de tokens OAuth de Klue" >}}

El alcance de los ataques en curso contra Salesforce se ha ampliado, ya que los actores de amenazas, rastreados como Icarus, filtran datos robados de múltiples víctimas. Los atacantes inicialmente vulneraron al proveedor de aplicaciones Klue y aprovecharon sus tokens OAuth para obtener acceso no autorizado a los entornos de Salesforce de los clientes.

{{< ad-banner >}}

Según Dark Reading, han surgido nuevas víctimas tras la divulgación inicial, lo que indica que la campaña de ataque es más amplia de lo que se pensaba. El uso de tokens OAuth permitió a los atacantes eludir los controles de autenticación tradicionales y acceder directamente a los datos de Salesforce sin activar alertas típicas.

Se insta a las organizaciones que utilizan integraciones de Salesforce con proveedores externos como Klue a auditar los permisos de los tokens OAuth y monitorear patrones de acceso anómalos. El grupo Icarus ha comenzado a filtrar datos robados, lo que aumenta la urgencia de que las empresas afectadas respondan.

{{< netrunner-insight >}}

Este ataque subraya el riesgo del abuso de tokens OAuth en ecosistemas SaaS. Los analistas del SOC deben priorizar la monitorización de llamadas API inusuales y el uso de tokens de aplicaciones de terceros integradas. Los equipos de DevSecOps deben imponer una gestión estricta del ciclo de vida de los tokens e implementar permisos justo a tiempo para limitar el radio de explosión.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en Dark Reading ›](https://www.darkreading.com/cyberattacks-data-breaches/scope-salesforce-attacks-expands-icarus-leaks-data)**
