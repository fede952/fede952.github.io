---
title: "Pacotes npm Maliciosos Visam Usuários de Ferramentas da Alibaba com RAT Multiplataforma"
date: "2026-08-04T09:40:19Z"
original_date: "2026-08-03T18:43:53"
lang: "pt"
translationKey: "malicious-npm-packages-target-alibaba-tool-users-with-cross-platform-rat"
slug: "malicious-npm-packages-target-alibaba-tool-users-with-cross-platform-rat"
author: "NewsBot (Validated by Federico Sella)"
description: "Pesquisadores descobrem 18 pacotes npm maliciosos, incluindo 'lib-mtop', que entregam um RAT multiplataforma a usuários de ferramentas de desenvolvimento da Alibaba em um ataque direcionado à cadeia de suprimentos."
original_url: "https://thehackernews.com/2026/08/18-malicious-npm-packages-deliver-cross.html"
source: "The Hacker News"
severity: "High"
target: "Usuários de ferramentas de desenvolvimento da Alibaba"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Pesquisadores descobrem 18 pacotes npm maliciosos, incluindo 'lib-mtop', que entregam um RAT multiplataforma a usuários de ferramentas de desenvolvimento da Alibaba em um ataque direcionado à cadeia de suprimentos.

{{< cyber-report severity="High" source="The Hacker News" target="Usuários de ferramentas de desenvolvimento da Alibaba" >}}

Pesquisadores de segurança cibernética identificaram um novo conjunto de 18 pacotes npm maliciosos projetados para atingir usuários das ferramentas de desenvolvimento da Alibaba. O ataque faz parte de uma campanha sofisticada e direcionada à cadeia de suprimentos de software que se concentra especificamente em ambientes de língua chinesa, indicando um alto nível de reconhecimento e localização.

{{< ad-banner >}}

Um dos pacotes, 'lib-mtop', é um pacote sem escopo que compartilha o mesmo nome de um pacote privado da Alibaba, uma técnica clássica de typosquatting. Isso sugere que os atacantes estão tentando enganar desenvolvedores que possam instalar erroneamente o pacote malicioso em vez do legítimo, obtendo assim uma posição em seus ambientes de desenvolvimento.

Os pacotes maliciosos entregam um trojan de acesso remoto (RAT) multiplataforma às vítimas, que pode fornecer aos atacantes controle remoto sobre os sistemas comprometidos. A natureza multiplataforma do RAT indica que ele foi projetado para afetar uma ampla gama de sistemas operacionais, aumentando o impacto potencial do ataque.

{{< netrunner-insight >}}

Este ataque ressalta a importância de verificar a autenticidade dos pacotes, especialmente ao usar pacotes privados ou internos. Analistas de SOC e engenheiros de DevSecOps devem implementar verificações rigorosas de proveniência de pacotes, como usar arquivos de bloqueio e verificar a integridade dos pacotes, e monitorar conexões de rede inesperadas de máquinas de desenvolvimento. Além disso, considere usar um registro privado com listas de permissão para prevenir ataques de typosquatting.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/08/18-malicious-npm-packages-deliver-cross.html)**
