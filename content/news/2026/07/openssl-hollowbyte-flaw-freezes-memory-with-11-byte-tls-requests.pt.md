---
title: "Falha HollowByte do OpenSSL Congela Memória com Requisições TLS de 11 Bytes"
date: "2026-07-18T08:44:53Z"
original_date: "2026-07-17T20:20:53"
lang: "pt"
translationKey: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
slug: "openssl-hollowbyte-flaw-freezes-memory-with-11-byte-tls-requests"
author: "NewsBot (Validated by Federico Sella)"
description: "Um bug de negação de serviço no OpenSSL, apelidado de HollowByte, permite que invasores congelem a memória do servidor usando pequenas requisições TLS. A Equipe Vermelha da Okta o reportou; a correção foi lançada sem CVE."
original_url: "https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html"
source: "The Hacker News"
severity: "High"
target: "Servidores OpenSSL em sistemas glibc"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Um bug de negação de serviço no OpenSSL, apelidado de HollowByte, permite que invasores congelem a memória do servidor usando pequenas requisições TLS. A Equipe Vermelha da Okta o reportou; a correção foi lançada sem CVE.

{{< cyber-report severity="High" source="The Hacker News" target="Servidores OpenSSL em sistemas glibc" >}}

Uma vulnerabilidade de negação de serviço recém-divulgada no OpenSSL, denominada HollowByte pela Equipe Vermelha da Okta, permite que um invasor exaura a memória do servidor com apenas 11 bytes de dados de handshake TLS. A falha faz com que um servidor OpenSSL sem patch aloque até 131 KB de memória para uma mensagem que nunca chega, e em sistemas que usam glibc, essa memória não é liberada até que o processo seja reiniciado.

{{< ad-banner >}}

O OpenSSL lançou a correção em junho de 2026 sem atribuir um identificador CVE, emitir um aviso ou notar a mudança no changelog. A Equipe Vermelha da Okta, que descobriu e reportou o bug, publicou detalhes após a correção ser lançada. A vulnerabilidade afeta servidores OpenSSL executados em sistemas baseados em glibc, tornando-os suscetíveis a ataques de exaustão de memória.

Embora o ataque exija apenas um único ClientHello TLS de 11 bytes, o impacto pode ser severo em ambientes onde os processos OpenSSL são de longa duração e lidam com muitas conexões simultâneas. Organizações que executam OpenSSL em glibc devem priorizar a aplicação da atualização de junho de 2026 para evitar possíveis condições de negação de serviço.

{{< netrunner-insight >}}

Este é um vetor clássico de exaustão de recursos que contorna a limitação de taxa tradicional porque o tráfego malicioso se parece com handshakes TLS normais. Analistas de SOC devem monitorar picos repentinos no uso de memória em servidores OpenSSL, e equipes de DevSecOps devem verificar se a atualização do OpenSSL de junho de 2026 foi implantada, mesmo sem um CVE. A ausência de um CVE não reduz o risco operacional—trate isso como um patch de alta prioridade.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/openssl-hollowbyte-flaw-could-freeze.html)**
