---
title: "Botnet RustDuck sequestra roteadores e câmeras para DDoS"
date: "2026-07-01T10:41:08Z"
original_date: "2026-06-30T17:45:25"
lang: "pt"
translationKey: "rustduck-botnet-hijacks-routers-cameras-for-ddos"
author: "NewsBot (Validated by Federico Sella)"
description: "Uma nova família de malware de dois estágios chamada RustDuck está sequestrando roteadores residenciais, câmeras IP, caixas Android e servidores mal protegidos para construir uma rede DDoS, rastreada desde fevereiro de 2026."
original_url: "https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html"
source: "The Hacker News"
severity: "High"
target: "Roteadores, câmeras IP, caixas Android, servidores"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Uma nova família de malware de dois estágios chamada RustDuck está sequestrando roteadores residenciais, câmeras IP, caixas Android e servidores mal protegidos para construir uma rede DDoS, rastreada desde fevereiro de 2026.

{{< cyber-report severity="High" source="The Hacker News" target="Roteadores, câmeras IP, caixas Android, servidores" >}}

Pesquisadores do XLab da QiAnXin estão rastreando uma nova família de malware de dois estágios chamada RustDuck desde fevereiro de 2026. O botnet sequestra roteadores residenciais, câmeras IP, caixas Android e servidores mal protegidos, unindo-os em uma rede projetada para derrubar sites e serviços online por meio de ataques DDoS.

{{< ad-banner >}}

O malware é notável por ter sido reescrito em Rust, uma linguagem com segurança de memória que dificulta a análise e engenharia reversa. Embora o tamanho atual do botnet não seja massivo, sua rápida evolução e adaptabilidade representam uma ameaça crescente à infraestrutura da internet.

RustDuck representa uma mudança no desenvolvimento de botnets, aproveitando os recursos de desempenho e segurança do Rust para criar malware mais resiliente e difícil de detectar. O objetivo final é construir uma rede DDoS robusta capaz de derrubar alvos importantes.

{{< netrunner-insight >}}

Para analistas de SOC: monitore tráfego de saída incomum de dispositivos IoT e roteadores, pois a infecção em dois estágios do RustDuck pode escapar de assinaturas tradicionais. Equipes DevSecOps devem impor segmentação de rede rigorosa e desabilitar serviços desnecessários em dispositivos expostos para reduzir a superfície de ataque.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/06/rustduck-botnet-rebuilds-in-rust-to.html)**
