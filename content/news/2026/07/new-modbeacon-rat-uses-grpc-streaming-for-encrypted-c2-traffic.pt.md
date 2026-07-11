---
title: "Novo MODBEACON RAT Usa Streaming gRPC para Tráfego C2 Criptografado"
date: "2026-07-11T08:43:59Z"
original_date: "2026-07-10T13:15:23"
lang: "pt"
translationKey: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
slug: "new-modbeacon-rat-uses-grpc-streaming-for-encrypted-c2-traffic"
author: "NewsBot (Validated by Federico Sella)"
description: "O grupo Silver Fox, ligado à China, implanta o MODBEACON RAT baseado em Rust via envenenamento de SEO, usando streaming gRPC para comunicação C2 criptografada."
original_url: "https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html"
source: "The Hacker News"
severity: "High"
target: "Usuários Windows via instaladores falsificados"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

O grupo Silver Fox, ligado à China, implanta o MODBEACON RAT baseado em Rust via envenenamento de SEO, usando streaming gRPC para comunicação C2 criptografada.

{{< cyber-report severity="High" source="The Hacker News" target="Usuários Windows via instaladores falsificados" >}}

O grupo de cibercrime Silver Fox, ligado à China, foi atribuído a um novo trojan de acesso remoto (RAT) baseado em Rust chamado MODBEACON. O malware usa streaming gRPC para tráfego criptografado de comando e controle (C2), tornando a detecção mais desafiadora.

{{< ad-banner >}}

De acordo com a empresa chinesa de segurança cibernética QiAnXin, o Silver Fox propaga o MODBEACON por meio de instaladores falsificados usando técnicas de envenenamento de SEO. Embora o grupo possa parecer uma operação de baixa sofisticação e alta atividade, suas verdadeiras capacidades organizacionais são mais avançadas.

O uso de streaming gRPC para comunicação C2 representa uma técnica nova para malware, pois aproveita HTTP/2 e buffers de protocolo para se misturar com o tráfego legítimo. As equipes de segurança devem monitorar tráfego gRPC incomum e investigar sites de download envenenados por SEO.

{{< netrunner-insight >}}

Analistas de SOC devem adicionar análise de tráfego gRPC aos seus pipelines de detecção, pois o uso de RPCs de streaming pelo MODBEACON pode evadir assinaturas de rede tradicionais. As equipes de DevSecOps devem verificar a integridade dos downloads de software e considerar bloquear domínios conhecidos de envenenamento de SEO. Este RAT ressalta a necessidade de caça proativa a ameaças contra malware baseado em Rust.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/new-modbeacon-rat-uses-grpc-streaming.html)**
