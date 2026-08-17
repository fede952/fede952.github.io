---
title: "Campaña de phishing con temática SPID dirigida a las credenciales de usuarios italianos"
date: "2026-08-17T07:50:54Z"
original_date: "2026-08-03T11:05:05"
lang: "es"
translationKey: "spid-themed-phishing-campaign-targets-italian-users-credentials"
slug: "spid-themed-phishing-campaign-targets-italian-users-credentials"
author: "NewsBot (Validated by Federico Sella)"
description: "CERT-AGID advierte de una nueva campaña de phishing que abusa de la marca SPID y AgID para robar datos personales y bancarios mediante dominios que contienen 'spid' y 'gov'."
original_url: "https://cert-agid.gov.it/news/phishing-a-tema-spid-in-corso/"
source: "CERT-AgID"
severity: "Medium"
target: "Usuarios italianos de SPID"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CERT-AGID advierte de una nueva campaña de phishing que abusa de la marca SPID y AgID para robar datos personales y bancarios mediante dominios que contienen 'spid' y 'gov'.

{{< cyber-report severity="Medium" source="CERT-AgID" target="Usuarios italianos de SPID" >}}

CERT-AGID ha identificado una campaña de phishing en curso que abusa del tema SPID (Sistema Público de Identidad Digital) para adquirir fraudulentamente información personal y bancaria de usuarios italianos. La campaña utiliza los nombres y logotipos oficiales de AgID y SPID para aumentar su credibilidad, lo que la hace particularmente engañosa.

{{< ad-banner >}}

Los atacantes están utilizando múltiples dominios que incorporan los términos 'spid' y 'gov' en sus nombres, una táctica diseñada para engañar a los usuarios haciéndoles creer que están interactuando con servicios gubernamentales legítimos. Este enfoque explota la confianza que los usuarios depositan en dominios y marcas de apariencia oficial.

Si bien el vector de ataque exacto (por ejemplo, correo electrónico, SMS) no se especifica en el aviso, el objetivo de la campaña es claro: recolectar datos sensibles. Se recomienda a los usuarios verificar la autenticidad de cualquier comunicación que solicite información personal o bancaria y reportar mensajes sospechosos a las autoridades correspondientes.

{{< netrunner-insight >}}

Para los analistas de SOC, esta campaña subraya la importancia de monitorear dominios similares que combinen términos de marcas confiables con 'gov' o TLD similares. Implemente reglas de filtrado de correo electrónico que marquen mensajes que contengan dichos dominios y eduque a los usuarios para verificar las URL antes de hacer clic. Los equipos de DevSecOps deberían considerar integrar fuentes de reputación de dominios en su pila de seguridad para bloquear automáticamente estos dominios de phishing.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en CERT-AgID ›](https://cert-agid.gov.it/news/phishing-a-tema-spid-in-corso/)**
