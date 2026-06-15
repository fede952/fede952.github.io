---
title: "Hackers ligados à China backdooraram software de login Linux por quase uma década"
date: "2026-06-15T13:04:59Z"
original_date: "2026-06-12T18:17:55"
lang: "pt"
translationKey: "china-linked-hackers-backdoored-linux-login-software-for-nearly-a-decade"
author: "NewsBot (Validated by Federico Sella)"
description: "Um grupo de origem chinesa conhecido como Velvet Ant comprometeu componentes PAM e OpenSSH, escondendo-se em sistemas de login Linux por quase dez anos sem detecção."
original_url: "https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html"
source: "The Hacker News"
severity: "High"
target: "Sistemas de login Linux (PAM, OpenSSH)"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Um grupo de origem chinesa conhecido como Velvet Ant comprometeu componentes PAM e OpenSSH, escondendo-se em sistemas de login Linux por quase dez anos sem detecção.

{{< cyber-report severity="High" source="The Hacker News" target="Sistemas de login Linux (PAM, OpenSSH)" >}}

Um ator de ameaças ligado à China, rastreado como Velvet Ant, foi descoberto ter backdoorado componentes centrais de login do Linux, incluindo PAM (Pluggable Authentication Modules) e OpenSSH, permitindo-lhes manter acesso persistente por quase uma década. O grupo teve como alvo uma rede onde incorporaram seu backdoor profundamente na pilha de autenticação, tornando-o resistente a procedimentos de limpeza padrão.

{{< ad-banner >}}

De acordo com a empresa de segurança Sygnia, os atacantes exploraram a confiança depositada no software de login para evadir detecção. Ao modificar os próprios mecanismos que controlam o acesso do usuário, garantiram que seu ponto de apoio sobrevivesse a atualizações do sistema e varreduras de segurança de rotina. A campanha destaca a crescente sofisticação de grupos patrocinados por estados ao mirar infraestruturas fundamentais.

O comprometimento ressalta a necessidade de as organizações monitorarem a integridade de componentes críticos do sistema além da detecção típica de endpoints. Defensores devem considerar monitoramento de integridade de arquivos para módulos PAM e binários SSH, bem como análise comportamental de logs de autenticação para identificar anomalias indicativas de processos de login backdoorados.

{{< netrunner-insight >}}

Para analistas de SOC e equipes DevSecOps, este é um lembrete contundente de que os atacantes estão mirando a própria camada de autenticação. Implemente verificações de integridade em tempo de execução nos binários PAM e OpenSSH e considere o uso de monitoramento em nível de kernel para detectar adulterações. Além disso, revise alterações na autenticação baseada em chave SSH e na configuração do PAM como parte de seus playbooks de resposta a incidentes.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em The Hacker News ›](https://thehackernews.com/2026/06/china-linked-hackers-backdoored-linux.html)**
