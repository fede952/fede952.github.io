---
title: "PCs Industriais ABB B&R Atingidos por Múltiplas CVEs: RCE, DoS, Envenenamento de DNS"
date: "2026-05-22T10:21:58Z"
original_date: "2026-05-21T12:00:00"
lang: "pt"
translationKey: "abb-b-r-pcs-hit-by-multiple-cves-rce-dos-dns-poisoning"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerta sobre vulnerabilidades em PCs industriais ABB B&R. Uma atualização está disponível. Atacantes podem obter execução remota de código, DoS, envenenamento de cache DNS ou roubo de dados."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02"
source: "CISA"
severity: "High"
target: "PCs industriais ABB B&R"
cve: "CVE-2023-45229"
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerta sobre vulnerabilidades em PCs industriais ABB B&R. Uma atualização está disponível. Atacantes podem obter execução remota de código, DoS, envenenamento de cache DNS ou roubo de dados.

{{< cyber-report severity="High" source="CISA" target="PCs industriais ABB B&R" cve="CVE-2023-45229" >}}

A ABB divulgou vulnerabilidades afetando várias linhas de produtos de PCs industriais B&R, incluindo APC4100, APC910, C80, MPC3100, PPC1200, PPC900 e APC2200. As falhas, rastreadas como CVE-2023-45229 a CVE-2023-45237, permitem que atacantes baseados em rede executem código remoto, lancem ataques de negação de serviço, envenenem caches DNS ou extraiam informações sensíveis.

{{< ad-banner >}}

O aviso lista versões afetadas para cada produto, com atualizações disponíveis para remediar os problemas. Por exemplo, versões do APC4100 abaixo de 1.09 são vulneráveis, enquanto a versão 1.09 está corrigida. Da mesma forma, versões do APC910 até e incluindo 1.25 são afetadas. A ABB recomenda atualizar para as versões de firmware mais recentes imediatamente.

Dado o contexto de sistemas de controle industrial (ICS), essas vulnerabilidades representam riscos significativos para ambientes de tecnologia operacional. Organizações que usam PCs ABB B&R afetados devem priorizar a correção, especialmente se os dispositivos estiverem expostos a redes não confiáveis.

{{< netrunner-insight >}}

Para analistas de SOC, monitore o tráfego de rede em busca de consultas DNS anômalas ou conexões inesperadas de PCs B&R. Equipes DevSecOps devem inventariar todos os dispositivos afetados e aplicar as atualizações de firmware o mais rápido possível, pois essas CVEs permitem execução remota de código sem autenticação. Considere segmentar redes ICS para limitar a exposição.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-02)**
