---
title: "Afiliado do Ransomware Akira Contorna EDR via Modo de Segurança e Exfiltra Dados"
date: "2026-08-16T07:35:41Z"
original_date: "2026-08-13T20:47:02"
lang: "pt"
translationKey: "akira-ransomware-affiliate-bypasses-edr-via-safe-mode-exfiltrates-data"
slug: "akira-ransomware-affiliate-bypasses-edr-via-safe-mode-exfiltrates-data"
author: "NewsBot (Validated by Federico Sella)"
description: "Afiliado do ransomware Akira desativa EDR iniciando no Modo de Segurança com Rede, rouba dados, mas falha na criptografia. Saiba como se defender."
original_url: "https://www.bleepingcomputer.com/news/security/akira-hackers-disable-edr-with-safe-mode-steal-data-but-fail-to-encrypt/"
source: "BleepingComputer"
severity: "High"
target: "Soluções de Detecção e Resposta de Endpoint (EDR)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Afiliado do ransomware Akira desativa EDR iniciando no Modo de Segurança com Rede, rouba dados, mas falha na criptografia. Saiba como se defender.

{{< cyber-report severity="High" source="BleepingComputer" target="Soluções de Detecção e Resposta de Endpoint (EDR)" >}}

Foi observado que um afiliado do ransomware Akira desativa soluções de detecção e resposta de endpoint (EDR) em sistemas comprometidos reiniciando a máquina no Modo de Segurança com Rede. Essa técnica permite que o atacante opere sem monitoramento EDR, pois muitas ferramentas de segurança não carregam no Modo de Segurança.

{{< ad-banner >}}

O afiliado conseguiu exfiltrar dados sensíveis da rede da vítima, mas a fase de criptografia do ataque falhou. Isso sugere que, embora o bypass do EDR tenha sido eficaz, outros controles de segurança ou problemas operacionais impediram que o payload final do ransomware fosse executado corretamente.

Este incidente destaca a importância de endurecer as configurações de inicialização e monitorar reinicializações inesperadas do sistema, especialmente no Modo de Segurança. As organizações também devem garantir que as soluções EDR tenham proteção contra adulteração ativada e que a inicialização no Modo de Segurança seja restrita ou monitorada.

{{< netrunner-insight >}}

Para analistas de SOC, este é um lembrete de que bypasses de EDR podem ser tão simples quanto uma reinicialização no Modo de Segurança. Monitore eventos incomuns de desligamento/reinicialização e considere desabilitar a inicialização no Modo de Segurança via senhas de BIOS/UEFI ou política de grupo. O DevSecOps deve garantir que os agentes EDR estejam configurados para iniciar no Modo de Segurança e que a proteção contra adulteração seja aplicada para prevenir essa técnica comum de evasão.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em BleepingComputer ›](https://www.bleepingcomputer.com/news/security/akira-hackers-disable-edr-with-safe-mode-steal-data-but-fail-to-encrypt/)**
