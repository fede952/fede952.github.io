---
title: "Lançamentos Maliciosos do LiteLLM no PyPI Ligados ao Hack do Trivy Expõem Mais de 2.100 Organizações"
date: "2026-08-17T07:48:06Z"
original_date: "2026-08-12T08:04:52"
lang: "pt"
translationKey: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
slug: "malicious-litellm-releases-on-pypi-linked-to-trivy-hack-expose-2100-orgs"
author: "NewsBot (Validated by Federico Sella)"
description: "Dois pacotes maliciosos do LiteLLM no PyPI roubaram chaves de nuvem, chaves SSH e muito mais. Dados da CloudSEK sugerem que mais de 2.100 organizações podem estar expostas."
original_url: "https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html"
source: "The Hacker News"
severity: "High"
target: "Usuários do LiteLLM no PyPI"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Dois pacotes maliciosos do LiteLLM no PyPI roubaram chaves de nuvem, chaves SSH e muito mais. Dados da CloudSEK sugerem que mais de 2.100 organizações podem estar expostas.

{{< cyber-report severity="High" source="The Hacker News" target="Usuários do LiteLLM no PyPI" >}}

Duas versões maliciosas do LiteLLM foram publicadas no PyPI e permaneceram disponíveis por aproximadamente 40 minutos em março. Esses pacotes continham código de roubo de credenciais projetado para coletar uma ampla gama de segredos, incluindo chaves de acesso à nuvem, chaves privadas SSH, tokens do Kubernetes e senhas de banco de dados de qualquer sistema que os instalasse.

{{< ad-banner >}}

A empresa de inteligência de ameaças CloudSEK obteve um conjunto de dados construído a partir de aproximadamente 434.000 arquivos que os atacantes capturaram. A análise desse conjunto de dados sugere que a exposição pode afetar mais de 2.100 organizações, destacando a escala potencial do comprometimento.

O incidente está ligado ao hack anterior do Trivy, indicando um ataque coordenado à cadeia de suprimentos. Organizações que instalaram o LiteLLM do PyPI durante a janela afetada devem imediatamente rotacionar todas as credenciais expostas e investigar sinais de acesso não autorizado.

{{< netrunner-insight >}}

Este incidente ressalta a necessidade crítica de vigilância na cadeia de suprimentos de software. Analistas de SOC devem monitorar quaisquer instalações das versões maliciosas do LiteLLM e priorizar a rotação de credenciais para quaisquer segredos potencialmente expostos. Equipes de DevSecOps devem impor verificações rigorosas de integridade de pacotes e considerar o uso de espelhos privados ou arquivos de bloqueio com hashes para mitigar tais riscos.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/08/malicious-litellm-releases-tied-to.html)**
