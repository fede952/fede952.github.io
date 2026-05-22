---
title: "CISA Alerta sobre Falhas no ABB B&R Automation Runtime que Permitem Sequestro de Sessão"
date: "2026-05-22T10:20:32Z"
original_date: "2026-05-21T12:00:00"
lang: "pt"
translationKey: "cisa-warns-of-abb-b-r-automation-runtime-flaws-allowing-session-hijack"
author: "NewsBot (Validated by Federico Sella)"
description: "Múltiplas vulnerabilidades no ABB B&R Automation Runtime anteriores à versão 6.4 podem permitir que invasores sequestrem sessões ou executem código. O aviso da CISA ICSA-26-141-04 detalha as correções."
original_url: "https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04"
source: "CISA"
severity: "Medium"
target: "ABB B&R Automation Runtime"
cve: "CVE-2025-3449"
cvss: 6.1
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Múltiplas vulnerabilidades no ABB B&R Automation Runtime anteriores à versão 6.4 podem permitir que invasores sequestrem sessões ou executem código. O aviso da CISA ICSA-26-141-04 detalha as correções.

{{< cyber-report severity="Medium" source="CISA" target="ABB B&R Automation Runtime" cve="CVE-2025-3449" cvss="6.1" >}}

A CISA divulgou o aviso ICSA-26-141-04 detalhando múltiplas vulnerabilidades no ABB B&R Automation Runtime, uma plataforma de software usada em automação industrial. As falhas, identificadas pela análise interna de segurança da B&R, afetam versões anteriores à 6.4 e incluem CVE-2025-3449 (identificadores de sessão previsíveis), CVE-2025-3448 (cross-site scripting) e CVE-2025-11498 (neutralização inadequada de elementos de fórmula em arquivos CSV). Um invasor não autenticado poderia explorá-las para sequestrar sessões remotas ou executar código no contexto do navegador de um usuário.

{{< ad-banner >}}

A vulnerabilidade mais grave, CVE-2025-3449, reside no componente System Diagnostic Manager (SDM) e possui uma pontuação CVSS v3 de 6.1. Ela permite que um invasor não autenticado baseado em rede assuma sessões já estabelecidas devido à geração de números ou identificadores previsíveis. O SDM está desabilitado por padrão no Automation Runtime 6, reduzindo a exposição, mas as organizações devem verificar se ele permanece desligado, a menos que seja explicitamente necessário.

A ABB lançou a versão 6.4 do Automation Runtime para corrigir esses problemas. Dado o uso do produto em todo o setor de energia mundialmente, a CISA insta os operadores a aplicar a atualização prontamente. O aviso observa que a exploração bem-sucedida pode levar à execução remota de código ou ao sequestro de sessão, representando um risco significativo para ambientes de controle industrial.

{{< netrunner-insight >}}

Para analistas de SOC: priorize a correção de instâncias do Automation Runtime, especialmente aquelas com SDM ativado. A falha de ID de sessão previsível (CVE-2025-3449) é trivialmente explorável pela rede. As equipes de DevSecOps devem garantir que o SDM permaneça desabilitado em produção e validar que nenhuma instância exposta seja acessível a partir de redes não confiáveis. Monitore atividades de sessão anômalas como um sinal de detecção.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em CISA ›](https://www.cisa.gov/news-events/ics-advisories/icsa-26-141-04)**
