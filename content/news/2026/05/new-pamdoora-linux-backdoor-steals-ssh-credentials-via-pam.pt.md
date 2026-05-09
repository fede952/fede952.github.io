---
title: "Novo Backdoor PamDOORa para Linux Rouba Credenciais SSH via PAM"
date: "2026-05-09T08:29:08Z"
original_date: "2026-05-08T08:41:00"
lang: "pt"
translationKey: "new-pamdoora-linux-backdoor-steals-ssh-credentials-via-pam"
author: "NewsBot (Validated by Federico Sella)"
description: "Um novo backdoor para Linux chamado PamDOORa, vendido em um fórum de crimes cibernéticos russo por US$ 1.600, usa módulos PAM para fornecer acesso SSH persistente com uma combinação de senha mágica e porta TCP."
original_url: "https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html"
source: "The Hacker News"
severity: "High"
target: "Servidores SSH Linux"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Um novo backdoor para Linux chamado PamDOORa, vendido em um fórum de crimes cibernéticos russo por US$ 1.600, usa módulos PAM para fornecer acesso SSH persistente com uma combinação de senha mágica e porta TCP.

{{< cyber-report severity="High" source="The Hacker News" target="Servidores SSH Linux" >}}

Pesquisadores de segurança cibernética descobriram um novo backdoor para Linux chamado PamDOORa, anunciado no fórum de crimes cibernéticos russo Rehub por US$ 1.600 por um ator de ameaças conhecido como 'darkworm'. O backdoor é projetado como um kit de ferramentas de pós-exploração baseado em Pluggable Authentication Module (PAM), permitindo acesso SSH persistente através de uma combinação de uma senha mágica e uma porta TCP específica.

{{< ad-banner >}}

O PamDOORa opera interceptando a autenticação SSH por meio de módulos PAM maliciosos, permitindo que atacantes contornem credenciais normais e obtenham acesso não autorizado. O uso de módulos PAM torna o backdoor furtivo, pois ele se integra ao fluxo de autenticação padrão do sistema Linux.

A venda de tais ferramentas em fóruns de crimes cibernéticos destaca a crescente mercantilização de ferramentas de ataque sofisticadas. As organizações são aconselhadas a monitorar padrões incomuns de autenticação SSH e garantir que as configurações do PAM sejam auditadas regularmente.

{{< netrunner-insight >}}

Para analistas de SOC, detectar o PamDOORa requer monitoramento de conexões SSH inesperadas em portas não padrão e correlação com alterações nos módulos PAM. As equipes de DevSecOps devem impor um gerenciamento rigoroso de configuração do PAM e considerar o monitoramento de integridade de arquivos para /etc/pam.d/ e bibliotecas relacionadas. Este backdoor ressalta a importância de tratar o PAM como um limite crítico de segurança.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/05/new-linux-pamdoora-backdoor-uses-pam.html)**
