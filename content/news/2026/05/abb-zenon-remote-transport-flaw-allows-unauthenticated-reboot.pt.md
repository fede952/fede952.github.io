---
title: "Falha no Transporte Remoto do ABB Zenon Permite Reinicialização Não Autenticada"
date: "2026-05-28T10:50:49Z"
original_date: "2026-05-26T12:00:00"
lang: "pt"
translationKey: "abb-zenon-remote-transport-flaw-allows-unauthenticated-reboot"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerta sobre CVE-2025-8754 no ABB Ability Zenon, permitindo reinicializações não autorizadas do sistema via Serviço de Transporte Remoto. Nenhuma exploração ativa relatada."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03"
source: "CISA"
severity: "High"
target: "Sistemas ABB Ability Zenon"
cve: "CVE-2025-8754"
cvss: 7.5
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerta sobre CVE-2025-8754 no ABB Ability Zenon, permitindo reinicializações não autorizadas do sistema via Serviço de Transporte Remoto. Nenhuma exploração ativa relatada.

{{< cyber-report severity="High" source="CISA" target="Sistemas ABB Ability Zenon" cve="CVE-2025-8754" cvss="7.5" >}}

A CISA publicou um aviso (ICSA-26-146-03) detalhando uma vulnerabilidade de falta de autenticação no Serviço de Transporte Remoto do ABB Ability Zenon. A falha, rastreada como CVE-2025-8754 com pontuação CVSS de 7,5, permite que um invasor acione uma reinicialização do sistema sem credenciais adequadas. As versões afetadas variam de 7.50 a 14.

{{< ad-banner >}}

A exploração requer acesso prévio à rede, pois o invasor já deve estar na mesma rede que o sistema Zenon alvo. A ABB observa que, nas configurações padrão, o serviço zensyssrv.exe é iniciado automaticamente, mas os usuários devem configurar uma senha para usar o Serviço de Transporte Remoto. No momento da redação, não há evidências de exploração ativa na natureza.

O aviso destaca a ampla implantação do ABB Ability Zenon em setores de infraestrutura crítica, incluindo sistemas Químico, Energia, Saúde e Água e Esgoto em todo o mundo. As organizações que usam versões afetadas devem aplicar imediatamente as mitigações ou atualizações fornecidas pela ABB para evitar possíveis ataques de negação de serviço.

{{< netrunner-insight >}}

Para analistas de SOC: priorize o segmentação de rede para limitar a exposição dos sistemas Zenon e garanta que as senhas do Serviço de Transporte Remoto estejam configuradas e sejam fortes. As equipes de DevSecOps devem verificar se o serviço zensyssrv.exe não está exposto a redes não confiáveis e aplicar patches do fornecedor assim que estiverem disponíveis. Dado o CVSS 7,5 e o impacto em infraestrutura crítica, trate isso como uma descoberta de alta prioridade, mesmo sem exploração ativa.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-146-03)**
