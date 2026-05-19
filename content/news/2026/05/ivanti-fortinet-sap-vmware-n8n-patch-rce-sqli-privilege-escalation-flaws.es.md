---
title: "Ivanti, Fortinet, SAP, VMware, n8n corrigen fallos de RCE, SQLi y escalada de privilegios"
date: "2026-05-19T10:36:29Z"
original_date: "2026-05-18T10:54:05"
lang: "es"
translationKey: "ivanti-fortinet-sap-vmware-n8n-patch-rce-sqli-privilege-escalation-flaws"
author: "NewsBot (Validated by Federico Sella)"
description: "Múltiples proveedores publican parches de seguridad para vulnerabilidades críticas, incluyendo Ivanti Xtraction CVE-2026-8043 (CVSS 9.6) que podría provocar divulgación de información o ataques del lado del cliente."
original_url: "https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html"
source: "The Hacker News"
severity: "Critical"
target: "Ivanti Xtraction"
cve: "CVE-2026-8043"
cvss: 9.6
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Múltiples proveedores publican parches de seguridad para vulnerabilidades críticas, incluyendo Ivanti Xtraction CVE-2026-8043 (CVSS 9.6) que podría provocar divulgación de información o ataques del lado del cliente.

{{< cyber-report severity="Critical" source="The Hacker News" target="Ivanti Xtraction" cve="CVE-2026-8043" cvss="9.6" >}}

Ivanti, Fortinet, n8n, SAP y VMware han publicado parches de seguridad que abordan múltiples vulnerabilidades que podrían ser explotadas para elusión de autenticación y ejecución remota de código. La falla más crítica es CVE-2026-8043 en Ivanti Xtraction, con una puntuación CVSS de 9.6, que permite el control externo de un nombre de archivo, lo que lleva a divulgación de información o ataques del lado del cliente.

{{< ad-banner >}}

Otros proveedores también abordaron problemas de alta gravedad, incluyendo vulnerabilidades de inyección SQL y escalada de privilegios. Se insta a las organizaciones a priorizar el parcheo de estas fallas, especialmente aquellas expuestas a internet, ya que podrían encadenarse para un compromiso total del sistema.

Aunque aún no se ha reportado explotación activa, la amplia superficie de ataque y las altas puntuaciones CVSS justifican atención inmediata por parte de los equipos de seguridad. El escaneo regular de vulnerabilidades y la gestión de parches son críticos para mitigar los riesgos.

{{< netrunner-insight >}}

Los analistas del SOC deben priorizar el parche de Ivanti Xtraction CVE-2026-8043 debido a su puntuación CVSS crítica y su potencial para ataques del lado del cliente. Los equipos de DevSecOps deben verificar que todos los sistemas afectados estén actualizados y monitorear cualquier signo de explotación, ya que el control externo de nombres de archivo puede llevar a la exfiltración de datos o movimiento lateral.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/05/ivanti-fortinet-sap-vmware-n8n-patch.html)**
