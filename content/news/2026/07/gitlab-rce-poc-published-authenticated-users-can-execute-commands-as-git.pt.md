---
title: "PoC de RCE no GitLab Publicado: Usuários Autenticados Podem Executar Comandos como Git"
date: "2026-07-27T10:37:15Z"
original_date: "2026-07-25T10:14:26"
lang: "pt"
translationKey: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
slug: "gitlab-rce-poc-published-authenticated-users-can-execute-commands-as-git"
author: "NewsBot (Validated by Federico Sella)"
description: "Um exploit de prova de conceito para uma falha de execução remota de código no GitLab foi divulgado, visando servidores autogerenciados 18.11.3 sem patch. Usuários autenticados podem executar comandos como o usuário git."
original_url: "https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html"
source: "The Hacker News"
severity: "High"
target: "GitLab autogerenciado 18.11.3"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Um exploit de prova de conceito para uma falha de execução remota de código no GitLab foi divulgado, visando servidores autogerenciados 18.11.3 sem patch. Usuários autenticados podem executar comandos como o usuário git.

{{< cyber-report severity="High" source="The Hacker News" target="GitLab autogerenciado 18.11.3" >}}

Em 24 de julho de 2026, pesquisadores de segurança da depthfirst publicaram um exploit de prova de conceito funcional para uma vulnerabilidade de execução remota de código no GitLab. A falha, corrigida pelo GitLab em 10 de junho de 2026, permite que qualquer usuário autenticado com acesso de push a um projeto execute comandos arbitrários como o usuário git em servidores GitLab autogerenciados 18.11.3 que não aplicaram a atualização.

{{< ad-banner >}}

O exploit aproveita um notebook Jupyter malicioso comprometido em um projeto. Quando o atacante abre o diff do commit, o notebook malicioso desencadeia um vazamento de heap, permitindo a execução de comandos. Essa técnica contorna os controles típicos de autenticação e não requer privilégios especiais além do acesso padrão ao projeto.

Organizações que executam instâncias autogerenciadas do GitLab devem verificar imediatamente se aplicaram o patch de 10 de junho. A disponibilidade pública do código do exploit aumenta o risco de exploração ativa, especialmente para instâncias expostas à internet. As equipes de defesa devem monitorar commits incomuns de notebooks Jupyter e atividade inesperada do usuário git.

{{< netrunner-insight >}}

Este exploit ressalta o perigo do atraso na aplicação de patches em plataformas CI/CD autogerenciadas. Analistas de SOC devem priorizar a detecção de processos anômalos do usuário git e uploads inesperados de notebooks Jupyter. Equipes DevSecOps devem impor uma janela de patch rigorosa para o GitLab e considerar a segmentação de rede para limitar a exposição de instâncias autogerenciadas.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/07/researcher-publishes-gitlab-rce-poc.html)**
