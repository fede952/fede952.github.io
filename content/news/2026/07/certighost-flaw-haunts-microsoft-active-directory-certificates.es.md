---
title: "La falla 'Certighost' acecha los certificados de Microsoft Active Directory"
date: "2026-07-29T09:36:19Z"
original_date: "2026-07-28T16:38:48"
lang: "es"
translationKey: "certighost-flaw-haunts-microsoft-active-directory-certificates"
slug: "certighost-flaw-haunts-microsoft-active-directory-certificates"
author: "NewsBot (Validated by Federico Sella)"
description: "Microsoft parcheó una vulnerabilidad de alta gravedad que permite la escalada de privilegios en entornos Active Directory. Los analistas de SOC deberían priorizar la aplicación del parche."
original_url: "https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates"
source: "Dark Reading"
severity: "High"
target: "Servicios de certificados de Microsoft Active Directory"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Microsoft parcheó una vulnerabilidad de alta gravedad que permite la escalada de privilegios en entornos Active Directory. Los analistas de SOC deberían priorizar la aplicación del parche.

{{< cyber-report severity="High" source="Dark Reading" target="Servicios de certificados de Microsoft Active Directory" >}}

Microsoft ha parcheado una vulnerabilidad de alta gravedad en los Servicios de certificados de Active Directory, denominada 'Certighost', que podría permitir a un atacante escalar privilegios y comprometer un entorno de Active Directory. La falla fue revelada por Dark Reading el 28 de julio de 2026.

{{< ad-banner >}}

La vulnerabilidad afecta el proceso de inscripción de certificados, permitiendo que un actor de amenazas con acceso de bajo nivel eleve sus privilegios a administrador de dominio. Esto podría llevar al compromiso total de la infraestructura de AD, incluida la capacidad de falsificar certificados y suplantar a cualquier usuario o dispositivo.

Se insta a las organizaciones que utilizan los Servicios de certificados de Microsoft Active Directory a aplicar las últimas actualizaciones de seguridad de inmediato. La vulnerabilidad subraya la naturaleza crítica de los servicios de certificados para mantener la confianza en los entornos de AD.

{{< netrunner-insight >}}

Este es un vector de ataque clásico contra servicios de certificados de AD. Asegúrese de que sus plantillas de certificados estén endurecidas y que los permisos de inscripción estén estrictamente controlados. Aplique el parche de inmediato y supervise solicitudes de certificados inusuales o escaladas de privilegios.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en Dark Reading ›](https://www.darkreading.com/vulnerabilities-threats/certighost-flaw-microsoft-active-directory-certificates)**
