---
title: "Fallo Ill Bloom drena $3.1 millones de carteras cripto mediante frases de recuperación débiles"
date: "2026-07-10T10:19:16Z"
original_date: "2026-07-10T09:00:05"
lang: "es"
translationKey: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
slug: "ill-bloom-flaw-drains-3-1m-from-crypto-wallets-via-weak-recovery-phrases"
author: "NewsBot (Validated by Federico Sella)"
description: "Atacantes explotan una vulnerabilidad en la generación de frases de recuperación de carteras de criptomonedas, denominada Ill Bloom, para robar $3.1 millones en un barrido coordinado."
original_url: "https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html"
source: "The Hacker News"
severity: "High"
target: "carteras de criptomonedas"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Atacantes explotan una vulnerabilidad en la generación de frases de recuperación de carteras de criptomonedas, denominada Ill Bloom, para robar $3.1 millones en un barrido coordinado.

{{< cyber-report severity="High" source="The Hacker News" target="carteras de criptomonedas" >}}

La firma de seguridad Coinspect ha revelado una vulnerabilidad en el software de carteras de criptomonedas, llamada Ill Bloom, que permite a los atacantes drenar fondos explotando la aleatoriedad débil en la generación de frases de recuperación. El fallo afecta a cómo algunas carteras crean la frase mnemotécnica que controla el acceso a los fondos de la cartera. Cuando la aleatoriedad es insuficiente, un atacante puede calcular la frase y obtener control total sobre la cartera.

{{< ad-banner >}}

Coinspect confirmó que los atacantes ya han explotado esta vulnerabilidad en un barrido coordinado en mayo, robando aproximadamente $3.1 millones de múltiples carteras. La fecha exacta y el alcance completo del ataque no se han revelado, pero el incidente resalta la importancia crítica de la generación segura de números aleatorios en aplicaciones criptográficas.

Se recomienda a los usuarios de carteras verificar que su software utilice generadores de números aleatorios criptográficamente seguros y considerar migrar fondos a carteras con implementaciones de aleatoriedad auditadas. Los desarrolladores deben revisar sus fuentes de entropía y asegurar el cumplimiento de estándares de la industria como BIP39.

{{< netrunner-insight >}}

Este incidente subraya el peligro de confiar en entropía débil en la generación de claves criptográficas. Los analistas del SOC deben monitorear transacciones inusuales de carteras o movimientos masivos de fondos, mientras que los ingenieros DevSecOps deben auditar toda generación de números aleatorios en aplicaciones críticas de seguridad. Siempre asuma que la aleatoriedad predecible será explotada.

{{< /netrunner-insight >}}

---

**[Leer el artículo completo en The Hacker News ›](https://thehackernews.com/2026/07/attackers-exploit-ill-bloom.html)**
