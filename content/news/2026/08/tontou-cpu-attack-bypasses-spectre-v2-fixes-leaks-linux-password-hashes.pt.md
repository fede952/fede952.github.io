---
title: "Ataque TONTOU à CPU contorna correções do Spectre v2 e vaza hashes de senhas do Linux"
date: "2026-08-10T08:26:15Z"
original_date: "2026-08-06T18:03:45"
lang: "pt"
translationKey: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
slug: "tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes"
author: "NewsBot (Validated by Federico Sella)"
description: "Pesquisadores desenvolvem ataque TONTOU que contorna mitigações recentes do Spectre v2, vazando com sucesso segredos, incluindo hashes de senhas de sistemas Linux."
original_url: "https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/"
source: "BleepingComputer"
severity: "High"
target: "sistemas Linux"
cve: null
cvss: null
kev: null
tags: ["news", "cybersecurity"]
news-categories: ["cybersecurity"]
layout: "news"
draft: false
---

Pesquisadores desenvolvem ataque TONTOU que contorna mitigações recentes do Spectre v2, vazando com sucesso segredos, incluindo hashes de senhas de sistemas Linux.

{{< cyber-report severity="High" source="BleepingComputer" target="sistemas Linux" >}}

Pesquisadores de segurança revelaram um novo ataque de execução especulativa, apelidado de TONTOU, que contorna mitigações recentes para a vulnerabilidade Spectre v2. O ataque tem como alvo os mecanismos de predição de desvio da CPU, que foram previamente corrigidos para prevenir vazamentos por canais laterais. Ao explorar uma lacuna nessas defesas, os pesquisadores conseguiram extrair dados sensíveis da memória do kernel de máquinas Linux.

{{< ad-banner >}}

A prova de conceito demonstra a gravidade do problema ao vazar com sucesso hashes de senhas do sistema alvo. Isso indica que o ataque poderia ser usado para comprometer credenciais de usuários e potencialmente escalar privilégios. As descobertas destacam o desafio contínuo de mitigar completamente ataques de canal lateral por execução especulativa, já que novas variações continuam a surgir apesar das correções anteriores.

Embora os pesquisadores ainda não tenham divulgado todos os detalhes técnicos, seu trabalho ressalta a necessidade de vigilância contínua na segurança da CPU. Administradores de sistemas são aconselhados a monitorar atualizações dos fabricantes de CPU e das distribuições Linux, e a considerar medidas adicionais de endurecimento, como randomização do layout do espaço de endereço do kernel (KASLR) e atualizações de microcódigo.

{{< netrunner-insight >}}

Este ataque é um lembrete claro de que as vulnerabilidades de execução especulativa não estão totalmente resolvidas. Analistas de SOC devem priorizar a aplicação de patches e monitorar quaisquer indicadores de exploração, enquanto engenheiros de DevSecOps devem revisar seus modelos de ameaça para riscos de canal lateral. Dado o potencial de vazar hashes de senhas, atenção imediata às atualizações do kernel Linux e ao microcódigo da CPU é justificada.

{{< /netrunner-insight >}}

---

**[Leia o artigo completo em BleepingComputer ›](https://www.bleepingcomputer.com/news/security/new-tontou-cpu-attack-bypasses-spectre-v2-fixes-leaks-linux-password-hashes/)**
