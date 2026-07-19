---
title: "Falha de DDoS HollowByte incha memória do servidor OpenSSL com payload de 11 bytes"
date: "2026-07-19T09:04:58Z"
original_date: "2026-07-17T17:56:21"
lang: "pt"
translationKey: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
slug: "hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload"
author: "NewsBot (Validated by Federico Sella)"
description: "Uma vulnerabilidade chamada HollowByte permite que atacantes não autenticados causem uma condição de negação de serviço em servidores OpenSSL com um payload malicioso de apenas 11 bytes."
original_url: "https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/"
source: "BleepingComputer"
severity: "High"
target: "servidores OpenSSL"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Uma vulnerabilidade chamada HollowByte permite que atacantes não autenticados causem uma condição de negação de serviço em servidores OpenSSL com um payload malicioso de apenas 11 bytes.

{{< cyber-report severity="High" source="BleepingComputer" target="servidores OpenSSL" >}}

Uma vulnerabilidade recém-descoberta, denominada HollowByte, permite que atacantes não autenticados causem uma condição de negação de serviço (DoS) em servidores OpenSSL ao enviar um payload especialmente criado de apenas 11 bytes. A falha explora ineficiências na alocação de memória, fazendo com que a memória do servidor inche e eventualmente esgote os recursos disponíveis.

{{< ad-banner >}}

O ataque não requer autenticação e pode ser executado remotamente, tornando-se uma ameaça significativa para qualquer organização que dependa do OpenSSL para comunicações seguras. O tamanho mínimo do payload permite que atacantes amplifiquem seu impacto com largura de banda limitada, potencialmente sobrecarregando servidores com esforço mínimo.

Embora nenhum identificador CVE tenha sido atribuído ainda, a vulnerabilidade foi divulgada ao projeto OpenSSL, e patches são esperados. Enquanto isso, os administradores são aconselhados a monitorar o uso de memória e implementar limitação de taxa ou regras de detecção de intrusão para mitigar possíveis explorações.

{{< netrunner-insight >}}

Para analistas de SOC, este é um vetor clássico de DoS de baixa largura de banda e alto impacto que pode contornar defesas volumétricas tradicionais. As equipes de DevSecOps devem priorizar a aplicação de patches assim que disponíveis e considerar a implementação de alertas de monitoramento de memória para detectar crescimento anômalo. O payload de 11 bytes torna este um candidato ideal para inclusão em regras de detecção de ameaças.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em BleepingComputer ›](https://www.bleepingcomputer.com/news/security/hollowbyte-ddos-flaw-bloats-openssl-server-memory-with-11-byte-payload/)**
