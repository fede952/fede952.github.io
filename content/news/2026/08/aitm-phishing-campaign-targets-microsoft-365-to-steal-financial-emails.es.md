---
title: "Campaña de phishing AitM dirigida a Microsoft 365 para robar correos financieros"
date: "2026-08-08T07:47:42Z"
original_date: "2026-08-07T10:38:27"
lang: "es"
translationKey: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
slug: "aitm-phishing-campaign-targets-microsoft-365-to-steal-financial-emails"
author: "NewsBot (Validated by Federico Sella)"
description: "El phishing generalizado impulsado por correo electrónico utiliza adversary-in-the-middle para secuestrar cuentas de Microsoft 365, con el objetivo de recopilar correos de nómina y finanzas."
original_url: "https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html"
source: "The Hacker News"
severity: "High"
target: "Cuentas de Microsoft 365"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

El phishing generalizado impulsado por correo electrónico utiliza adversary-in-the-middle para secuestrar cuentas de Microsoft 365, con el objetivo de recopilar correos de nómina y finanzas.

{{< cyber-report severity="High" source="The Hacker News" target="Cuentas de Microsoft 365" >}}

Investigadores de ciberseguridad han identificado una campaña de phishing activa y generalizada impulsada por correo electrónico que aprovecha técnicas de adversary-in-the-middle (AitM) para comprometer cuentas de Microsoft 365. El objetivo principal de la campaña es identificar al personal clave involucrado en los flujos de trabajo financieros y exfiltrar las comunicaciones de correo electrónico relacionadas, particularmente las relativas a nómina y finanzas.

{{< ad-banner >}}

Los atacantes emplean proxies residenciales para disfrazar sus inicios de sesión maliciosos como tráfico de consumidores ordinario, evadiendo así la detección por parte de los controles de seguridad que normalmente marcan direcciones IP sospechosas. Esta técnica permite a los atacantes mantener la persistencia y el acceso a las cuentas comprometidas sin generar alarmas inmediatas.

Las organizaciones que utilizan Microsoft 365 deben estar alerta ante tales intentos de phishing AitM, que a menudo evaden la autenticación multifactor al retransmitir credenciales y tokens de sesión en tiempo real. El enfoque de la campaña en datos financieros sugiere un esfuerzo dirigido a facilitar el fraude financiero o el compromiso de correo electrónico empresarial (BEC).

{{< netrunner-insight >}}

Esta campaña subraya la necesidad de MFA resistente al phishing, como las llaves de seguridad FIDO2, y el monitoreo continuo de inicios de sesión anómalos, especialmente aquellos que se originan desde rangos de IP residenciales. Los equipos de SOC también deben priorizar las reglas de detección para kits de herramientas AitM y aplicar políticas de acceso condicional que restrinjan el acceso según las señales de riesgo. Los ingenieros de DevSecOps deben considerar la implementación de enlace de sesión y controles de cumplimiento del dispositivo para mitigar los ataques de retransmisión de tokens.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/08/microsoft-365-aitm-phishing-hijacks.html)**
