---
title: "Falhas Críticas no Carregador EV XCharge C6 Permitem Execução Remota de Código"
date: "2026-05-29T10:39:44Z"
original_date: "2026-05-28T12:00:00"
lang: "pt"
translationKey: "critical-flaws-in-xcharge-c6-ev-charger-allow-remote-code-execution"
author: "NewsBot (Validated by Federico Sella)"
description: "CISA alerta sobre vulnerabilidades não autenticadas em controladores de carregamento EV XCharge C6, incluindo CVE-2026-9037, com pontuação CVSS de 9,8."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08"
source: "CISA"
severity: "Critical"
target: "Controladores de carregamento EV XCharge C6"
cve: "CVE-2026-9037"
cvss: 9.8
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

CISA alerta sobre vulnerabilidades não autenticadas em controladores de carregamento EV XCharge C6, incluindo CVE-2026-9037, com pontuação CVSS de 9,8.

{{< cyber-report severity="Critical" source="CISA" target="Controladores de carregamento EV XCharge C6" cve="CVE-2026-9037" cvss="9.8" >}}

A CISA publicou um aviso (ICSA-26-148-08) detalhando múltiplas vulnerabilidades críticas em controladores de carregamento de veículos elétricos XCharge C6. As falhas incluem download de código sem verificação de integridade (CWE-494), estouro de buffer baseado em pilha e inicialização de um recurso com padrão inseguro. A exploração bem-sucedida pode permitir que um invasor obtenha direitos de administrador ou execute código arbitrário no dispositivo.

{{< ad-banner >}}

A vulnerabilidade mais grave, CVE-2026-9037, envolve um mecanismo de atualização de firmware que não valida a autenticidade dos pacotes de firmware. Sem verificação de assinatura criptográfica, um invasor que possa interferir ou se passar pelo canal de gerenciamento pode instalar firmware não autorizado, levando à execução de código com altos privilégios. A pontuação CVSS v3 para esta vulnerabilidade é 9,8, indicando gravidade crítica.

A XCharge implantou uma atualização de firmware para todos os carregadores afetados a partir de 22 de maio de 2026. Os usuários são aconselhados a garantir que seus dispositivos estejam atualizados e a entrar em contato com o suporte da XCharge, se necessário. O produto afetado é amplamente implantado no setor de sistemas de transporte em vários países.

{{< netrunner-insight >}}

Para analistas de SOC, priorize o monitoramento de interfaces de gerenciamento de carregadores XCharge C6 quanto a acessos não autorizados ou solicitações anômalas de atualização de firmware. Equipes de DevSecOps devem impor segmentação de rede e aplicar o patch do fornecedor imediatamente, pois a falta de verificações de integridade torna esses dispositivos um alvo principal para ataques à cadeia de suprimentos.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-148-08)**
