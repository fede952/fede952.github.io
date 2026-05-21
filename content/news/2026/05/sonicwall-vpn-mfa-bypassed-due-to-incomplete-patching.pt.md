---
title: "MFA do SonicWall VPN contornado devido a correção incompleta"
date: "2026-05-21T10:35:14Z"
original_date: "2026-05-20T21:19:17"
lang: "pt"
translationKey: "sonicwall-vpn-mfa-bypassed-due-to-incomplete-patching"
author: "NewsBot (Validated by Federico Sella)"
description: "Atacantes realizam força bruta em credenciais VPN e contornam MFA em appliances SonicWall Gen6 SSL-VPN não corrigidos, implantando ferramentas de ransomware."
original_url: "https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/"
source: "BleepingComputer"
severity: "High"
target: "Appliances SonicWall Gen6 SSL-VPN"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Atacantes realizam força bruta em credenciais VPN e contornam MFA em appliances SonicWall Gen6 SSL-VPN não corrigidos, implantando ferramentas de ransomware.

{{< cyber-report severity="High" source="BleepingComputer" target="Appliances SonicWall Gen6 SSL-VPN" >}}

Observou-se que atacantes realizam força bruta em credenciais VPN e contornam a autenticação multifator (MFA) em appliances SonicWall Gen6 SSL-VPN. Os ataques exploram correções incompletas, permitindo que adversários implantem ferramentas comumente usadas em operações de ransomware.

{{< ad-banner >}}

A vulnerabilidade permite que atacantes obtenham acesso não autorizado a redes internas após comprometerem credenciais VPN. Uma vez dentro, podem se mover lateralmente e implantar cargas de ransomware, representando um risco significativo para organizações que dependem desses appliances para acesso remoto.

A SonicWall lançou patches para resolver o problema, mas a aplicação incompleta dessas atualizações deixa os sistemas expostos. As organizações são instadas a verificar se todos os patches recomendados estão totalmente instalados e a monitorar sinais de acesso VPN não autorizado.

{{< netrunner-insight >}}

Este incidente ressalta a importância crítica de uma gestão de patches completa. Analistas de SOC devem priorizar a verificação de que todos os appliances SonicWall Gen6 tenham o firmware mais recente e monitorar logs de VPN para padrões de autenticação anômalos. Equipes de DevSecOps devem considerar a implementação de camadas adicionais de MFA e segmentação de rede para mitigar tais contornos.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em BleepingComputer ›](https://www.bleepingcomputer.com/news/security/hackers-bypass-sonicwall-vpn-mfa-due-to-incomplete-patching/)**
