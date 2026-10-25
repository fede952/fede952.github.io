---
title: "Política de Privacidad"
description: "Cómo trata tus datos federicosella.com: herramientas que procesan todo localmente en el navegador sin subidas, analítica sin cookies, anuncios con consentimiento y enlaces de afiliado declarados."
date: 2026-07-04
lastmod: 2026-10-26
hidemeta: true
showToc: true
---

**Última actualización: 24 de octubre de 2026**

## 1. Responsable del tratamiento

**Federico Sella** — Italia
Email: [privacy@federicosella.com](mailto:privacy@federicosella.com)

## 2. En resumen

- **Las herramientas web de este sitio procesan tus datos localmente, en tu navegador.** Los archivos, contraseñas, imágenes y textos que introduces en las herramientas **nunca se suben** a ningún servidor, ni nuestro ni de terceros. La única excepción (la consulta de IP de NetGuard) se explica en la sección 3.
- Sin cuentas, sin newsletter, y nunca vendemos datos personales.
- El sitio se financia con **Google AdSense**. El banner de consentimiento de Google te pide permiso antes de usar cualquier cookie publicitaria.
- La analítica es **sin cookies** (Umami). En este sitio no hay Google Analytics.
- Algunas páginas contienen **enlaces de afiliado** claramente señalados (sección 7).
- Puedes cambiar o retirar tu consentimiento en cualquier momento desde **"Configuración de Cookies"** en el pie de página.

## 3. Las herramientas web: procesamiento local

Todas las herramientas interactivas del sitio (generador y auditor de contraseñas, limpiador EXIF, compresor de imágenes, generador de códigos QR, JWT inspector, escáner de secretos, conversores y el resto) funcionan en tu navegador con JavaScript y API web estándar como Web Crypto API y Canvas API. Los datos que introduces o los archivos que abres con ellas:

- se procesan **solo en tu dispositivo**;
- **nunca se transmiten** a nuestros servidores ni a terceros;
- se descartan al cerrar o recargar la página, salvo que guardes tú el resultado.

**Una excepción, intencionada:** **NetGuard** te muestra tu dirección IP pública y su ubicación aproximada. Para ello, tu navegador envía una petición al servicio de consulta de IP [ipwho.is](https://ipwho.is/). Como cualquier petición web, revela a ese servicio tu dirección IP (y el user-agent del navegador). No se envía nada más, y la petición solo se hace cuando pulsas Scan en NetGuard.

**Una segunda excepción, opcional:** el auditor de **PassFort** puede comprobar si una contraseña aparece en filtraciones de datos conocidas. Solo ocurre cuando pulsas **Check against known breaches**. Tu navegador calcula entonces el hash SHA-1 de la contraseña y envía solo sus 5 primeros caracteres al servicio Pwned Passwords de Have I Been Pwned en [api.pwnedpasswords.com](https://haveibeenpwned.com/Passwords) (k-anonimato); la contraseña y el resto del hash nunca se envían y la comparación se hace en tu dispositivo. Como cualquier petición web, revela a ese servicio tu dirección IP y el user-agent del navegador.

**Una tercera excepción, a petición:** el **Comprobador de SPF, DKIM y DMARC** consulta los registros DNS públicos de un dominio. Al pulsar **Comprobar**, tu navegador envía consultas DNS del dominio que escribiste (registros TXT de SPF, DMARC, selectores DKIM y BIMI, y registros MX) al resolver público DNS-over-HTTPS de Cloudflare, [cloudflare-dns.com](https://developers.cloudflare.com/1.1.1.1/privacy/public-dns-resolver/). No se envía nada más, y nada sale antes de pulsar el botón. Como cualquier petición web, revela a Cloudflare tu dirección IP y el user-agent del navegador.

Algunas herramientas ofrecen además enlaces a servicios externos (por ejemplo "comprobar esta URL en VirusTotal" en Link Hazmat, o los botones para compartir). Son enlaces normales: no se envía nada hasta que haces clic.

Puedes comprobarlo todo con las herramientas de desarrollo del navegador (pestaña Red).

## 4. Alojamiento y recursos de las páginas

Es un sitio estático alojado en **GitHub Pages** (GitHub, Inc.). Como cualquier alojamiento, GitHub trata tu dirección IP para servir las páginas y puede conservar registros del servidor por motivos de seguridad. Consulta la [GitHub Privacy Statement](https://docs.github.com/en/site-policy/privacy-policies/github-general-privacy-statement).

Las fuentes y las librerías JavaScript están **alojadas en este dominio**. El sitio no carga Google Fonts ni ninguna CDN pública, así que ver una página no envía peticiones a esos servicios.

## 5. Analítica (Umami, sin cookies)

Usamos [Umami](https://umami.is/) para contar visitas. Umami **no usa cookies** ni **identificadores persistentes**. Solo registra estadísticas anónimas y agregadas (páginas vistas, sitio de procedencia, tipo de navegador y dispositivo, país) que no pueden vincularse contigo. Como no se guardan datos personales ni se escribe nada en tu dispositivo, se basa en nuestro interés legítimo en saber qué contenido resulta útil.

## 6. Publicidad (Google AdSense)

La publicidad mantiene gratuitas todas las herramientas del sitio. Usamos **Google AdSense** (Google Ireland Ltd. / Google LLC). Para visitantes del EEE, Reino Unido y Suiza, la **plataforma de gestión del consentimiento certificada** de Google (IAB Transparency & Consent Framework) te pide tu elección antes de usar cualquier cookie publicitaria:

- Con consentimiento, Google y sus socios pueden mostrar **anuncios personalizados** y usar cookies publicitarias.
- Sin consentimiento, solo pueden mostrarse anuncios **no personalizados** o limitados, sin cookies de personalización.

Los anuncios aparecen solo en las páginas de herramientas y guías, nunca dentro de las herramientas. Cómo usa Google los datos de sitios asociados: [policies.google.com/technologies/partner-sites](https://policies.google.com/technologies/partner-sites). Gestiona tus preferencias de anuncios: [adssettings.google.com](https://adssettings.google.com).

## 7. Enlaces de afiliado

Algunas páginas recomiendan productos de terceros (por ejemplo una VPN o un gestor de contraseñas) mediante **enlaces de afiliado**, marcados con "Enlace de afiliado" junto al enlace. Si haces clic y compras algo, puedo recibir una comisión **sin ningún coste adicional para ti**. Las recomendaciones se eligen porque encajan con la herramienta que estás usando, no por la comisión.

Al hacer clic en un enlace de afiliado llegas a la web del socio, que puede establecer sus propias cookies para atribuir la recomendación. Eso ocurre en su sitio y bajo su política de privacidad. Este sitio no recibe de los socios ningún dato personal sobre ti, solo informes agregados de comisiones.

## 8. Bases jurídicas (RGPD)

- **Consentimiento** (art. 6(1)(a)): cookies publicitarias.
- **Interés legítimo** (art. 6(1)(f)): funcionamiento y seguridad del sitio, estadísticas agregadas sin cookies.

## 9. Tus derechos

Según el RGPD tienes derecho a acceder, rectificar y suprimir tus datos, a limitar u oponerte al tratamiento, a la portabilidad y a retirar el consentimiento en cualquier momento (desde **Configuración de Cookies** en el pie de página). Para ejercerlos, escribe a [privacy@federicosella.com](mailto:privacy@federicosella.com). También puedes reclamar ante la autoridad italiana ([Garante per la Protezione dei Dati Personali](https://www.garanteprivacy.it/)) o la de tu país (en España, la [AEPD](https://www.aepd.es/)).

## 10. Transferencias internacionales

Google y GitHub pueden tratar datos en Estados Unidos. Estas transferencias se basan en el **Marco de Privacidad de Datos UE–EE. UU.** y/o en **Cláusulas Contractuales Tipo**.

## 11. Conservación de datos

Este sitio **no guarda datos personales en sus propios servidores**: es un sitio estático sin base de datos. Umami solo conserva agregados anónimos. Google y los socios afiliados conservan los datos según sus propias políticas.

## 12. Menores

Este sitio no está dirigido a menores de 16 años y no recopilamos sus datos a sabiendas.

## 13. Cambios

Las actualizaciones se publicarán en esta página con una nueva fecha de "Última actualización".

## 14. Documentos relacionados

- [Política de Cookies](/es/cookies/)
- [Contacto](/es/contact/)
- ¿Buscas la política de privacidad de la app móvil **Pasta Stack**? Consulta [Pasta Stack — App Privacy Policy](/en/apps/pasta-stack/privacy/) (en inglés).
